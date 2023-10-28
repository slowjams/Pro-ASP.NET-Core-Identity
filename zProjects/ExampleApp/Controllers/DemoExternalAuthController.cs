using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace ExampleApp.Controllers
{
    public class DemoExternalAuthController : Controller  // demonstrate external authentication, you can consider it as Google Auth Service
    {
        private static string expectedID = "MyClientID";
        private static string expectedSecret = "MyClientSecret";
        private static List<UserRecord> users = new List<UserRecord> {  // simulate gmail account
            new UserRecord() 
            {
                Id = "1", Name = "Alice", EmailAddress = "alice@example.com", Password = "myexternalpassword", 
                Code = "12345", Token = "token1"
            },
            new UserRecord 
            {
                Id = "2", Name = "Dora", EmailAddress = "dora@example.com", Password = "myexternalpassword",
                Code = "56789", Token = "token2"
            }
        };

        public IActionResult Authenticate([FromQuery] ExternalAuthInfo info)  // <-----------------ee2.0, simulate Googe's SignIn page
        {
            return expectedID == info.client_id ? View((info, string.Empty)) : View((info, "Unknown Client"));
            /* < -----------------ee2.1.
             this Razor View prompt user to enter user name and password and then make a post request to the below handler
             with all value of ExternalAuthInfo are hidden as input
            */
        }

        [HttpPost]
        public IActionResult Authenticate(ExternalAuthInfo info, string email, string password)  // <---------ee3.0 when you click SignIn button
        {                                                                                        // simulate the post request for Googe's verification after users enter credentials
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(password))
            {
                ModelState.AddModelError("", "Email and password required");
            }
            else
            {
                UserRecord user = users.FirstOrDefault(u => u.EmailAddress.Equals(email) && u.Password.Equals(password));  // find whether the user exist in Google's database

                if (user != null)
                {
                    // localhost:5000/signin-external?code=12345&scope=openid email profile&state=xxx_
                    return Redirect(info.redirect_uri + $"?code={user.Code}&scope={info.scope}" + $"&state={info.state}");  //<------ee3.1.
                }
                else
                {
                    ModelState.AddModelError("", "Email or password incorrect");
                }
            }

            return View((info, ""));
        }

        [HttpPost]
        public IActionResult Exchange([FromBody] ExternalAuthInfo info)
        {
            UserRecord user = users.FirstOrDefault(user => user.Code.Equals(info.code));  // get user by auth code, but external servcie won't pass user'data in this step

            if (user == null || info.client_id != expectedID || info.client_secret != expectedSecret)
            {
                return Json(new { error = "unauthorized_client" });
            } else
            {
                return Json(new
                {
                    access_token = user.Token,
                    expires_in = 3600,
                    scope = "openid+email+profile",
                    token_type = "Bearer",
                    info.state
                });
            }
        }

        [HttpGet]
        /*  initialize request
        GET HTTP/1.1
        Host: xxx
        Accept: application/json
        Authorization: Bearer token1
        */
        public IActionResult Data([FromHeader] string authorization)  // authorization is "Bearer token1"
        {
            string token = authorization?[7..];
            UserRecord user = users.FirstOrDefault(user => user.Token.Equals(token));  // get user by token and pass user's data
            if (user != null)
            {
                return Json(new { user.Id, user.EmailAddress, user.Name });
            }
            else
            {
                return Json(new { error = "invalid_token" });
            }
        }
    }

    public class UserRecord
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string EmailAddress { get; set; }
        public string Password { get; set; }
        public string Code { get; set; }  // authorization code tells the request initiated application that the user 
                                          // has been authenticated and has granted access to the data specified by the scope
        public string Token { get; set; }
    }

    public class ExternalAuthInfo 
    {
        public string client_id { get; set; }
        public string client_secret { get; set; }
        public string redirect_uri { get; set; }
        public string scope { get; set; }
        public string state {  get; set; }
        public string response_type {  get; set; }
        public string grant_type {  get; set; }
        public string code {  get; set; }
    }
}
