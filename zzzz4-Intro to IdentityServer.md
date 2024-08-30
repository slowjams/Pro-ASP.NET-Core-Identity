## Intro to IdentityServer
==============================

 **State** and **PKCE** (Proof of Key Code Exchange) solves different problems, that means they cannot replace each other:


* State Parameter (stored on ClientApp) : 
Prevent Cross-Site Request Forgery (CSRF) attacks (Hacker tricks you to uses his auth code). Users uses browser.

* PKCE (Code Verifier stored on ClientApp, and Code Challenge stored on Authorization Server): Prevent authorization interception (Hacker steals your auth code)
Note that it only fits in native mobile desktop environment compared to State Parameter which fits the scenerio that users uses browser. Prerequisite knowledge in OS level URL scheme registration see https://www.oauth.com/oauth2-servers/redirect-uris/redirect-uris-native-apps/

Scenario: UserA ask webApp/nativeApp which is an photo process tool we, developers develop to post photos on behalf users to post photos to users' google drive

When **State** Parameter is not used:
* Both UserA and HackerB registered with webApp. HackerB gets the redirect URL which contains authorization code returned by Google but stops there. HackerB develops a malicious website, UserA previously signin google redirected by webApp before, and now UserA clicks on that malicious website/link which is the HackerB's redirect URL (to webApp), this request goes to webApp with UserA's cookie, webApp authenticates UserA because of the cookie and request access token of HackerB not UserA, so UserA's uploading photos in HackerB's google drive.

After **State** Parameter is used:
* Before UserA firstly signin google redirected by webApp, **ClientApp creates anti-forgery state token and store it in the server**, let's say this token is `abc123` (this token will be query string in the URL), and webApp also needs to associate this token with UserA's session id (for cookies later). HackerB does the same process, and the token is `xyz123` on the server. Now HackerB tricks UserA to redirect with HackerB's redirect URL (to webApp and `xyz123` as query string in this URl) request, when webApp receives this request from UserA, ClientApp retrieves the UserA session (by using cookie which contains session id) and find UserA's state token is `abc123` not `xyz123`, so webApp declines this request. Note that HackerB won't be able to know UserA's state token

When **PKCE** Parameter is not used:
* Now HackerB develops a malicious native app and it is installed on UserA's mobile so UserA has both valid nativeApp(mobile version of webApp) and maliciousApp.  After UserA firstly signin google (redirected by nativeApp in the beginning), google sends a redirection url of clientApp back to UserA, however, it is maliciousApp handles this request (to see why refer to the article above), now hackerB gets userA's auth code,  hackerB knows the nativeApp's client secret, for example, SPA or mobile app will expose client secret to the public (quoted from https://medium.com/@alysachan830/the-basics-of-oauth-2-0-authorization-code-implicit-flow-state-and-pkce-ed95d3478e1c)

When **PKCE** Parameter is used:
* When userA click signin with google on clientApp, clientApp generate a random value called **Code Verifier** (this code verifier also need to be associated with userA using session/cookie),  then clientApp hashes the Code Verifier and the result is called  **Code Challenge**, and clientApp sends the redirection url (google's signin url with code challenge being a query string) to userA, userA signin with his credentials and do a post request with this code challenge, so google's **authoriazation server will store this code challenge** (must be associated with auth code behind the scene). Google's authoriazation server sends a redirection url (contains auth code) to userA, even though it is maliciousApp that intercepts this request, HackerB doesn't know Code Verifier, HackerB might know Code Challenge since it is appended to the url which is easy to steal, but that doesn't matter as google's authoriazation server will need original Code Verifier and do a hash function on it to see if the result is same as code challenge before sending the final access token, only clientApp has the userA's Code Verifier.
 
==================================================================================================================

gfgfgfgfgf IdentityServer flow: client and IdentityServer both started and then client requests an Authorized endpoint

1. IdentityServer4.Hosting.IdentityServerMiddleware[0] Invoking IdentityServer endpoint: IdentityServer4.Endpoints.DiscoveryEndpoint for /.well-known/openid-configuration

2. IdentityServer4.Hosting.IdentityServerMiddleware[0] Invoking IdentityServer endpoint: IdentityServer4.Endpoints.DiscoveryKeyEndpoint for /.well-known/openid-configuration/jwks

3. IdentityServer4.Hosting.IdentityServerMiddleware[0] Invoking IdentityServer endpoint: IdentityServer4.Endpoints.AuthorizeEndpoint for /connect/authorize    request is below

4. IdentityServer4.ResponseHandling.AuthorizeInteractionResponseGenerator[0] Showing login: User is not authenticated

https://localhost:5005/connect/authorize?client_id=movies_mvc_client&redirect_uri=https%3A%2F%2Flocalhost%3A5002%2Fsignin-oidc&response_type=code&scope=openid%20profile&code_challenge=p-43fIBx17fDkH74dzXQ5UD-tLi06I-uZ2hLJC7VNrw&code_challenge_method=S256&response_mode=form_post&nonce=638567338983969349.MzMyMjUwMTAtYWFjNS00ODllLTgxZjMtMGNkNTE3NTExOGFkMzIzMzZkN2YtODlhZi00MTNjLTkzYWYtNzFhNGQ2NzQyYmUw&state=CfDJ8Fr2n1UxboNJlI8uHVA4skoRmwxF3pgfFy-1R72fnqWA4dAqaJo0zwcSXn1f0OMzSDtE0zcseq69CcVkUpTfC4Cgl2bcSfllF96NwxTlOQatNFzfQ7DPOPeAqBydoEIKbR43VlivPjLsO4WLcKZfsvWiGLNSnndq33GwGqPXX69qP6H2DGcYOCBh5UaCQIMb8Ez3q9VK3p93vs7S8dnOo1ebHBp3J-bqKiiZsI14jfTW02zqS6cUPBjjReuuibrw5dgDXgFTFvfWFFxw0HpZI2lZ50PYCUgUshLr42lOci4DlAisNH98xXqi0jZzDqTFenbInuz9WHkewizdyKYem4JKb-evVyrFP2m5aW2KdDJqJbvvQxax9Wr9fYL5ZkstdA&x-client-SKU=ID_NETSTANDARD2_0&x-client-ver=6.10.0.0


client redirect to
5. https://localhost:5005/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Dmovies_mvc_client%26redirect_uri%3Dhttps%253A%252F%252Flocalhost%253A5002%252Fsignin-oidc%26response_type%3Dcode%26scope%3Dopenid%2520profile%26code_challenge%3Dsb4TagoSL5dZm0yoKqrhPMFyVFzm7BqEKv1qPc0SJ2E%26code_challenge_method%3DS256%26response_mode%3Dform_post%26nonce%3D638567344972487423.NjNmNzM2MzUtMDc0NC00YjQxLWI4NzItYzI3ZjcyYjYzYzk5NDAxZWIwYTUtYTFkNC00Nzg4LWE5MTctMmI3Yzg2ZjQwNDkw%26state%3DCfDJ8Fr2n1UxboNJlI8uHVA4skp8iLAkLOvyhGMzQCakOhC1dxof-RstR40W6ffes6oyXipaodLvz41ZzWUHFlvxOCjgmqUMmvZY9nL1qAfTlJRk2ml6lxOmEPpZBosdqIWrHzXDjOzV6L6U0lYEEEstNSwoLAK3Q9PD-DOlqUtAjsVxfakrF4emTE00dqoGLMRwgnSpEUEXZZ-tuawPFBZu8d_GzpMWvCe4Z0zHPi4uNPbleTWP4dsr8hFWmV0Wa4o-zXHw0DCXISPzkwHIEPEHOmqvatYw8nPFY95HwRofik3GI3t3IoSYHfA2eFK3hIyXzywMCky8yxjMS85fxcfSQzZ33fC5B4vAMNaDGLLCG5f4zvRYFvdlUQe_hwvrH2oH7A%26x-client-SKU%3DID_NETSTANDARD2_0%26x-client-ver%3D6.10.0.0


after user login with username and password:


https://localhost:5005/connect/authorize/callback?client_id=movies_mvc_client&redirect_uri=https%3A%2F%2Flocalhost%3A5002%2Fsignin-oidc&response_type=code&scope=openid%20profile&code_challenge=0qFsZFA2lUjoYobYkwEktE5ii8ARXZ-oM14eLva_xoA&code_challenge_method=S256&response_mode=form_post&nonce=638568074213265770.MTgyY2Q1NjAtZWViNS00MDIzLTgyODgtNWIwOTFkOWM5YTlkMWE0ZDQxZjgtODk4Mi00ZDU5LTkyMTYtYjU5Mjk5Y2VlOTI2&state=CfDJ8Fr2n1UxboNJlI8uHVA4skpAT72lTOJwx9rBEUij3-3baXRptiWBNJq1EU2GKGd6g4v_w761APhA8twe8EeUk_mXB07hYn3GgVeXkVatqF5AaPhFbFmJp0jGGsyGgY_-BIAjAj_OHDtb7XDF9ye5M8AubOICEy4awzvEF-8KASsN5uKjz3D-xcAk5hx8961oXZWfBX_uj7wQe1nN86CT0kqBWyraNhZa-Nzw9oOXirHZ7l9ZLLCpIxuMD0cg85g3M8Vp07wopyxY42_bcOCUeE7dSYbD1oy-F_hhuFjAgBc175oBrbixdDcBXrYdsyCv2-ADa2gOqXryS82rljCXIrW0IDJj3-AH1kwdmS2TVEeD2PhEWDPpKliyyDCDUEifng&x-client-SKU=ID_NETSTANDARD2_0&x-client-ver=6.10.0.0"

IdentityServer4.Hosting.IdentityServerMiddleware: Information: Invoking IdentityServer endpoint: IdentityServer4.Endpoints.AuthorizeCallbackEndpoint for /connect/authorize/callback



IdentityServer4.Hosting.IdentityServerMiddleware: Information: Invoking IdentityServer endpoint: IdentityServer4.Endpoints.TokenEndpoint for /connect/token
IdentityServer4.Validation.TokenRequestValidator: Information: Token request validation success, {
  "ClientId": "movies_mvc_client",
  "ClientName": "Movies MVC Web App",
  "GrantType": "authorization_code",
  "AuthorizationCode": "****6EFB",
  "RefreshToken": "********",
  "Raw": {
    "client_id": "movies_mvc_client",
    "client_secret": "***REDACTED***",
    "code": "AD40D97E955E20034F81CA91F3CE03BB1E58614A4E8102781BD982DC34396EFB",
    "grant_type": "authorization_code",
    "redirect_uri": "https://localhost:5002/signin-oidc",
    "code_verifier": "Rq0hyWJoaOL1AkD9xWllf5mq_0sMMmR-q7nzQJ3z9k4"
  }
}

IdentityServer4.Hosting.IdentityServerMiddleware: Information: Invoking IdentityServer endpoint: IdentityServer4.Endpoints.UserInfoEndpoint for /connect/userinfo

IdentityServer4.ResponseHandling.UserInfoResponseGenerator: Information: Profile service returned the following claim types: given_name family_name

Identity token: eyJhbGciOiJSUzI1NiIsImtpZCI6IkNEOTlDNTM1QkJFRjEyRkY2OTg5MkNEN0Q0QjMzMkJFIiwidHlwIjoiSldUIn0.eyJuYmYiOjE3MjExMzgxOTcsImV4cCI6MTcyMTEzODQ5NywiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3Q6NTAwNSIsImF1ZCI6Im1vdmllc19tdmNfY2xpZW50Iiwibm9uY2UiOiI2Mzg1NjczNDk5MDM1NTk3NDIuTVRreU1EUm1aR010T1RaaFlTMDBNRFprTFRsalpEY3ROREkyWVRnMU56azBPR0l3TWpRd016aG1ZekF0WVRnMU5TMDBZVFJtTFdKak0yRXRZVFU0Tm1abE5UQmxORGRrIiwiaWF0IjoxNzIxMTM4MTk3LCJhdF9oYXNoIjoiNUpyT01BWWMxSUdzRmhNR3Q4dEpiQSIsInNfaGFzaCI6IjFoaGp3cnlRbkpJcDNMOGtKX0JockEiLCJzaWQiOiI0QUYxMzQ0MDg5NDAxRjRCM0NBNUM5MTY1QkQ4RkFGMSIsInN1YiI6IjVCRTg2MzU5LTA3M0MtNDM0Qi1BRDJELUEzOTMyMjIyREFCRSIsImF1dGhfdGltZSI6MTcyMTEzODE5NiwiaWRwIjoibG9jYWwiLCJhbXIiOlsicHdkIl19.RzYc1YEN8opVGf9ENz3jKifdz2ro56wbKbx3BoxzidpJH84oUFI1-Hr1shFciAPB418ksw_-_2caoRaD2mLRsj7o-tCwRJdFvQPdzp6uueIkO6lXQcZ69-EUZnRO-qIqL6vbRCLfn4IGg3QEkQh0Np2dRj_tD9nFN_7X3N4L2hP5ARbG1uyda48KRk_JDEML4p9955B3LwbGolZ6pyh8Xz6iA-eF1UJvMeAfcY-mFLhsRX92R9fETwbkGwflEi3bLtwfS8WO-YVcqj7yI8SFp_yjFlEQGsZ_zvn1kABNft7GcqqwYzjSzPFJ_ek_Xs3yCXtK-rKan7sr33ZIGFj3Hw

```json
{
  "nbf": 1721138197,
  "exp": 1721138497,
  "iss": "https://localhost:5005",
  "aud": "movies_mvc_client",
  "nonce": "638567349903559742.MTkyMDRmZGMtOTZhYS00MDZkLTljZDctNDI2YTg1Nzk0OGIwMjQwMzhmYzAtYTg1NS00YTRmLWJjM2EtYTU4NmZlNTBlNDdk",
  "iat": 1721138197,
  "at_hash": "5JrOMAYc1IGsFhMGt8tJbA",
  "s_hash": "1hhjwryQnJIp3L8kJ_BhrA",
  "sid": "4AF1344089401F4B3CA5C9165BD8FAF1",
  "sub": "5BE86359-073C-434B-AD2D-A3932222DABE",
  "auth_time": 1721138196,
  "idp": "local",
  "amr": [
    "pwd"
  ]
}
```

After User Click Logout (from Client Server 5002 to IdentityServer 5005)


https://localhost:5005/connect/endsession?post_logout_redirect_uri=https%3A%2F%2Flocalhost%3A5002%2Fsignout-callback-oidc&id_token_hint=eyJhbxxx
IdentityServer4.Hosting.IdentityServerMiddleware[0] Invoking IdentityServer endpoint: IdentityServer4.Endpoints.EndSessionEndpoint for /connect/endsession

info: IdentityServer4.Validation.EndSessionRequestValidator[0] End session request validation success
```json
{
  "ClientId": "movies_mvc_client",
  "ClientName": "Movies MVC Web App",
  "SubjectId": "5BE86359-073C-434B-AD2D-A3932222DABE",
  "PostLogOutUri": "https://localhost:5002/signout-callback-oidc",
  "State": "CfDJ8Fr2n1UxboNJlI8uHVA4skrersQnMvlg0Xe6UDjtZNZgCh0UU19uKQOeXE1aZqPFNj7nQuAC-aHSWPmoyZvdomtIxvdAAgKYHdZvt0yo3pyBMMaMZO31Iyr7x3Fv7v8CcY0ofebZl0x_m8kJ2SISAgoXfT7FYeiPj_a_cu3RqMr1",
  "Raw": {
      "post_logout_redirect_uri": "https://localhost:5002/signout-callback-oidc",
      "id_token_hint": "***REDACTED***",
      "state": "CfDJ8Fr2n1UxboNJlI8uHVA4skrersQnMvlg0Xe6UDjtZNZgCh0UU19uKQOeXE1aZqPFNj7nQuAC-aHSWPmoyZvdomtIxvdAAgKYHdZvt0yo3pyBMMaMZO31Iyr7x3Fv7v8CcY0ofebZl0x_m8kJ2SISAgoXfT7FYeiPj_a_cu3RqMr1",
      "x-client-SKU": "ID_NETSTANDARD2_0",
      "x-client-ver": "6.10.0.0"
  }
}
```

info: IdentityServer4.Hosting.IdentityServerMiddleware[0] Invoking IdentityServer endpoint: IdentityServer4.Endpoints.EndSessionCallbackEndpoint for /connect/endsession/cal

info: IdentityServer4.Endpoints.EndSessionCallbackEndpoint[0] Successful signout callback.

https://localhost:5005/Account/Logout?logoutId=CfDJ8Fr2n1UxboNJlIxxx



if you set (IdentityServerHost.Quickstart.UI) AutomaticRedirectAfterSignOut to true, then there is no "Click here to return to the Movies MVC Web App application" in https://localhost:5005/Account/Logout?logoutId=CfDJ8Fr2n1 page where you originally have to click to return to https://localhost:5002/ movie client, add a screenshot to explain

=======================================================================================

You might wonder why redirect_uri is needed when client_id is supplied in OAuth2, isn't that client app already registered its redirect url in authorization server? so only client_id is needed for the authorization server to look up and retrieve redirect_uri automatically as long as client_id is the correct one?

As pointed out in the OAuth 2.0 specification, the redirect_uri in the Authorization Request is optional. It's only necessary if the client hasn't previously registered a redirection endpoint, or if they've registered multiple redirection endpoints. Both cases are valid.

If there's a single pre-registered redirection endpoint, then the redirect_uri parameter can indeed be omitted.

=======================================================================================

Hybrid Flow, Authorization endpoint returns Id token/Access token while, authorization code flow returns all tokens from  Token Endpoint only

Authorization endpoint
Token Endpoint





===========================================================================================

## Request Pipelines

`7184`: `Client`  `5001`: `IdentityServer`  `7075`: `Api` (note that Api doesn't use `[Authorize]` at all, it is clientApp should use Authorize attribute)

```C#
public class ClientProgram  // https://localhost:7184
{
    public static void Main(string[] args)
    {
        builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme; 
            options.Authority = "https://localhost:5001/";
            options.ClientId = "imagegalleryclient";
            options.ClientSecret = "secret";
            options.ResponseType = "code";
        });
    }
}
```

A. Run Solution

https://localhost:7184  (goes to ImageGallery.Client's GalleryController's Index)


1. `AuthenticationMiddleware` calls `AuthenticateAsync()`  

2.  `AuthorizationMiddleware` calls default `ChallengeAsync()`

3. `OpenIdConnectHandler.HandleChallengeAsync()`
(a1) invoke `https://localhost:5001/.well-known/openid-configuration` and `https://localhost:5001/.well-known/openid-configuration/jwks`

redirect users to `https://localhost:5001/connect/authorize` (a2)

```C#
/*
https://localhost:5001/connect/authorize?client_id=imagegalleryclient&redirect_uri=https%3A%2F%2Flocalhost%3A7184%2Fsignin-oidc&response_type=code&scope=openid%20profile&code_challenge=gxNP3gQQtCv6ybY-1SzRhuJ2lAJcw4xfY63-N0VMp_M&code_challenge_method=S256&response_mode=form_post&nonce=638574178447973386.ZjQ1NjBhYzAtOTVjOC00OWQyLWFjOWUtYWEwYTIwYzNhMWU5ZGQ4NDU0MTktOGQyMi00ZmEzLTlkZjktMDQ4ZTY4MDhiMDM2&state=CfDJ8Fr2n1UxboNJlI8uHVA4skoqzWvRBESNmQtbapScbGyypqXNQqM3EO-KWHib-2DDMkYQWldSjTcokpFYtMjQJD5XN1rtDfaVAAwhUvzEo6e57hN8e2izgZZm4TuLTwaZpBDb1QsoIjGnD-aiIgb_7F9w1k0VBi34RIiLbwcsR-rxYokuDnAeZp0Ndx4TlExO158E9m-58DEigNRBCuaGPWSjZuw2fyT3Z4b6DblgZKSyTGjUwJfu7n8L01lr-CL3xjzc7ZW7Vws647ScwLFdbqAu_IEnDiEokswUxNGR4c6Th5roQZwVmq6T4HvQWGq2J0Xy9KFP6nfZbqLx_hKMht_cqC33G_HSbz_z_GmAJzw5igImxo8LjNRVazD18_t8oA&x-client-SKU=ID_NET8_0&x-client-ver=7.1.2.0
*/
```

4. `https://localhost:5001/connect/authorize` POST request goes to IdentityServer, `IdentityServerMiddleware`'s `AuthorizeEndpoint` handles it (q2 on IdentityServer Source Code)
and `AuthorizeEndpoint` redirects users with `/Account/Login` Razor page content with `ReturnUrl` set to `/connect/authorize/callback...` which flows from the Razor Page's `OnGet` to `OnPost`, the redirection request is below:

```C#
/*
https://localhost:5001/Account/Login?ReturnUrl=%2Fconnect%2Fauthorize%2Fcallback%3Fclient_id%3Dimagegalleryclient% 26redirect_uri%3Dhttps%253A%252F% 252Flocalhost%253A7184%252Fsignin-oidc %26response_type%3Dcode%26scope%3Dopenid%2520profile%26code_challenge%3DXXX
*/
```

5. User enter credentials, trigger `/Account/Login` post back to IdentityServer (i5), calls `HttpContext.SignInAsync("Cookie")` to **create user-to-idp cookie** (compared to Client calls SignInAsync in step 7, so there will be two cookies, one from user to client, and one from user to IdentityServer) so IdentityUser is transformed to ClaimsPrincipal which contains name claim such as "Emma", then AuthenticationTicket is added into cookie, then Razor Page (not `CookieAuthenticationHandler`) redirect users to `/connect/authorize/callback`

```C#
/*

/connect/authorize/callback?client_id=imagegalleryclient&redirect_uri=https%3A%2F%2Flocalhost%3A7184%2Fsignin-oidc&response_type=code&scope=openid%20profile&code_challenge=C65uIECsCXnqwGPFOlU1fbmZ9pXvKNxmvCx5v3kiHI4&code_challenge_method=S256&response_mode=form_post&nonce=638574267416022614.MDU0MTRjMjgtZTkyMC00YmFhLWJhYWItN2VhNTdhZTY4YmIxNGM0MjE0N2ItYjNjYy00NGMxLThiYjctYzc1NjY2MGNiNDll&state=CfDJ8Fr2n1UxboNJlI8uHVA4skp7SK2F0Vxutc5qOeTZGQyGWEPBj4A1Ehs8MXQJsYylUCPpd3NjXQEtUPQ5cNPS-ORlAw_pDzW5TDRJxEfm_3PziPZBlGE-vff_m3DJna4mOcM7R6vIZHKPsx5Stf2h7D9D5AAeeOeILPDWyJiKdODSRSZZCbPKIaspX5eDxN8E6_6OXjo5TLrk-qkpBiW36V9mWVXffF3OVF9EM0vkB-lkLbrTIMdO5QscZzs4s3vR8nbL6jclJMkPwiy5GDjgRDvDuqAI14LtVhAGdXfZr0xA3BXCu1Ocfht8I2bpb9PnLGVzAnCFFlgOEaWu6otftkQGoQJNt83lJd7OPFkCOHbxms8PbV3kBIw-C_ubRWRFmw&x-client-SKU=ID_NET8_0&x-client-ver=7.1.2.0"

*/
```

6. IDP's `IdentityServerMiddleware` handles `/connect/authorize/callback` (HttpContext.User contains "user = Emma" claim because of user-to-idp cookie created), its `AuthorizeCallbackEndpoint` (check c flag) handles this `/connect/authorize/callback` request to generate an auth code (c3.4), then a POST redirection request from user to client using client's pre-registration RedirectUris (`https://localhost:7184/signin-oidc`) with auth code (in body, not in querystring as the redirection is POST redirection) is initialize

```C#
/*  https://localhost:7184/signin-oidc POST
    body:
    {
        code: EA4785B99D609C359E14512C70724FFEFFC15F5EA445486B1B072E73CF3FF8CC-1   // <----------------auth code
        scope: openid+profile
        state: CfDJ8Fr2n1UxboNJlI8uHVA4skryuRiPt-1-mhFSMYxXnAqQXXX
        session_state: e35UPvqWXV_cxZ3bBNM-fZEpln9j5Qh4JrVxbX0L9is.28084428FDF3B4FCDC5EDB4D69D3DC4F
        iss: https://localhost:5001
    }
*/
```

7.  `https://localhost:7184/signin-oidc` is handled by `AuthenticationMiddleware` (e1) in ClientApp, then `OpenIdConnectHandler.HandleRequestAsync()` then its base handler `RemoteAuthenticationHandler.HandleRequestAsync()` (OpenIdConnectHandler, o flag, this is where `https://localhost:5001/connect/token` endpoint get called with auth code generated previously (o3.2) to get access token and id token). Note that idp's `TokenEndpoint` retrieve "who is the user that this ClientApp represents for" info based on the auth code clientApp pass (check ac flag,  note that idp has assoicate with users and auth code in the beginning when user is redirected to sign in idp in the first time ). The id token is validated in ClientApp, part of this validation is calculating the hash from the access token to see if it mathches the `at_hash` value in the id token, so access token takes part in the validation procedure of the identity token. If validation checks out, then a `ClaimIdentity` is created from the id token.  **Client calls `Context.SignInAsync()` with this id-token-based ClaimIdentity to create 'user-to-client' cookie** (o5.0) before redirecting users to its original request e.g home/index
Note that cookie can be:

**A**: `AuthenticationTicket` is created from id token, and since id token doesn't userinfo such "user = Emma" claim (note that **user-to-idp** cookie always contains "user = Emma" claim, since user signs in on IDP's end), so this **user-to-client** cookie won't have any user info claims such as "name", "role" etc

**B**: `OpenIdConnectOptions.GetClaimsFromUserInfoEndpoint` is set to `true`, then `OpenIdConnectHandler` will call `https://localhost:5001/connect/userinfo` (access token is required in the bear header with this request) to get userinfo from IDP. The scopes inside Access Token will be extracted such as "sub", "name", "given_name", "family_name" claims because of `IdentityResource`/`Resource`'s `ICollection<string>` of `UserClaims`. Then `IProfileService` will be used to generate those claims. (u1.6, check `TestUserProfileService` or `LocalUserProfileService` for example). Later `AuthenticationTicket` is created (o4.4), so now **user-to-client** cookie can contain user info claims such as "name", "role" etc. Note that the id token still won't contains 'UserClaims". It is not a good practice to let id token contains "user specific claims" from Userinfo endpoint.

Important thing to know, in the subsequent requst, only **user-to-client** cookie is needed for user to be authenticated, however if you develop logout functionality by only sign out this 
user-to-client cooke, it will have issue shows below.

8. A-Prerequisite knowledge for SignOut functionality , you have to do:

```C#
public class AuthenticationController : Controller
{
    [Authorize]
    public async Task Logout()
    {
        // clears the local cookie
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // clear IDP own session/cookie
        await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme); // <----------don't forget to call this one
    }
}
```

`HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme)` trigger below request (s flag):

```C#
/*
https://localhost:5001/connect/endsession?post_logout_redirect_uri=https%3A%2F%2Flocalhost%3A7184%2Fsignout-callback-oidc&id_token_hint=eyJhbGciOiJSUzxxxx
*/
```

and let's say you didn't clear IDP cookie, and after user click logout and request the resource again, at p1, the user is from IDP cookie, and at P2, it won't be `LoginPageResult` but `AuthorizeResult` (that's why users won't be showed with Login page again), then it just repeats step 6, 7, then user is still seems to be login

A special note on the "user-to-idp cookie" and "user-to-client" cookie. the former is created first on the IdentityServer's end i.e Login page, so the claims will be the data on the signin form (especially the "user = Emma" claim which probably won't be in id token). "user-to-client" cookie however it is created based on id token from idp (if `options.GetClaimsFromUserInfoEndpoint = true` then the process is a little bit different check the note above).

So if you don't clear IDP own session/cookie, and request the resource, resource will be returned to your with no 401 error (bug), behind the scene`AuthorizationMiddleware` calls `OpenIdConnectHandler.HandleChallengeAsync()` to repeat the communication to idp, after `https://localhost:7184/signin-oidc` is handled by client, Client calls `Context.SignInAsync()` again. If you request the resousrce again,  resource will be returned to you (still a bug), and this time `OpenIdConnectHandler.HandleChallengeAsync()` won't be called


8. B-Signout process

Inside Client App like `AuthenticationController` above , triggers `OpenIdConnectHandler.SignOutAsync()` which triggers `https://localhost:5001/connect/endsession` (sot flag),

```C#
/*  token_hint is the id token
https://localhost:5001/connect/endsession?post_logout_redirect_uri=https%3A%2F%2Flocalhost%3A7184%2Fsignout-callback-oidc&id_token_hint=eyJhbGciOiJSUzI1Nxxxx
*/
```

then `EndSessionEndpoint` hanldes this `connect/endsession` request, then redircts user to IdentityServer's Logout Razor page

```C#
/*
https://localhost:5001/Account/Logout?logoutId=CfDJ8Fr2n1UxboNJlI8uHVA4skoft053fXDUzUXvku1K6jgfyhhxxx
*/
```

9. check `e2` flag you will see inside `/Account/Logout` page, it calls `await HttpContext.SignOutAsync()` which clear out user-idp cookie, i.e clear user session


10. Send requests to API with access token. It is important to note that Api's `HttpContext.User`'s `ClaimsPrincipal` is constructed by `JwtBearerHandler` based on the access token (check j0.4 flag).


Important to know the Claims difference between the ClientApi and Api

```C#
// ClientApi
[HttpGet()]
public async Task<ActionResult<IEnumerable<Image>>> GetImages()
{
    var user = User;  // <-----------------------------------contains all "UserInfo" claims such as {given_name: Emma}, {family_name: Flagg}, {role: PayingUser}, {country: be} etc
    // ...
}

// Api
public async Task<IActionResult> Index()
{
    var user = User;  // <---------------------------doesn't contains some "UserInfo" claims like given_name, family_name, but contains {role: PayingUser}, {country: be} 
    // ...            // beause idp config has `new ApiResource("imagegalleryapi", "Image Gallery API", new [] { "role", "country" })`
}
```

Below shows how addition Claims such as "role"  is included in Access Token:

```C#
// IdentityServer's Config
public static IEnumerable<ApiResource> ApiResources =>
    new ApiResource[]
    {
        new ApiResource("imagegalleryapi", "Image Gallery API", new [] { "role" })  // role here results the access token to contains a role claim such as { "role" : "payinguser" }
        { 
            Scopes = { "xxx" } 
        },
    };

// Api
[HttpPost()]
[Authorize(Roles = "PayingUser")] // resource  is protected
public async Task<ActionResult<Image>> CreateImage([FromBody] ImageForCreation imageForCreation)
{
    var claimsPrincipal = User;   // contains { "role" : "payinguser" }
    // ...
}
```

There is an intesting thing that if you turn off role scope in client (remove `options.Scope.Add("roles")`) while IDP still have `new ApiResource("imagegalleryapi", "Image Gallery API", new [] { "role" }) `. This results the access token to have `{ "role": "PayingUser" }` claim so that if you put a debugger in API service's you can also see the HttpContext.User contains this role claim, but `HttpContext.User` in the Client's controller won't have this role claim

=========================================================================


## Token Lifetime Management

**Id tokens have very short default of `5 minutes` lifetime** as it is issued once to create `ClaimsIdentity`. So let's user-to-client cookie (that contains the `AuthenticateTicket` created based on id token in the first time) expires after 3 mins, then `OpenIdConnectHandler.ChallengeAsync()` is called, the id token can be used again to construct `ClaimsIdentity` without requiring users to signin again with idp. However, if the cookie expires after one hour, then user has to sign in with idp again

**Accesstokens have default of `1 hour` lifetime**

Note the **user-to-client cookie (that contains id token and access token) expiration time is controlled by `Client.IdentityTokenLifetime` when `OpenIdConnectOptions.UseTokenLifetime` is true**  (check `tl` flag). So if you set `Client.IdentityTokenLifetime = 12` on idp's end, it results the id token and accees token to contain { "exp" : xxxx }, so later in step 7- handling `https://localhost:7184/signin-oidc` when clientApp calls `Context.SignInAsync()` with this id-token-based ClaimIdentity to create 'user-to-client' cookie, the cookie expire time is set to match "12 seconds"

For `Client.AccessTokenLifetime = numberOfSeconds`, this have nothing to do with cookie, it is only used by idp's end to control the lifetime of the access token, so the Api's `JwtBearerHandler` need to honour this setting. 

So in a nutshell, `IdentityTokenLifetime` makes the id token contains a { "exp" : xxxx } and xxx will be used to set user-to-client cookie's expire time on ClientApp's end when `OpenIdConnectOptions.UseTokenLifetime` is true. While `AccessTokenLifetime` makes identity token contains  a { "exp" : yyyy } where yyy is mainly for idp to recieve and handle requests from Api's  `JwtBearerHandler` based on if the access token has expired

If you set `OpenIdConnectOptions.UseTokenLifetime` to `true` then refresh the page, it still remains signin (if you watch broswer closely, you will see the browser flash a request of `https://localhost:5001/connect/authorize`), why? because of the refresh token behiend the scene

`Client.AbsoluteRefreshTokenLifetime` is default to 30 days.

Note that by default `TokenValidationParameters.ClockSkew = TimeSpan.FromSeconds(300);  // 5 mins`.  `ClockSkew` is the addtional time (safety net) that idp ( as it uses `TokenValidationParameters` to validate access token passed by Api) applies when it comes to validate whether the access token is still valid, it does this to handle small offsets in out-of-sync clock times between the server where your idp live and where the Api server live as IDP and Api can be away from each other in very long distance, it takes time for the request that carries access token to reach to idp


```C#
public static class Config  // IDP
{
    // ...
    public static IEnumerable<Client> Clients =>
        new Client[]
        {
             new Client()
             {
                 AccessTokenLifetime = 3 // only valid for 3 second
             }
        }
}

// if you refresh the page, you still can access the Api resource until 5mins passes,if you want access token to expire quick e.g when in testing environment, then you do:

public class Program  // Api
{
    public static void Main(string[] args)
    {
        // ...
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = "https://localhost:5001";
                // ...                         
                options.TokenValidationParameters = new TokenValidationParameters()
                {                   
                    // ...
                    ClockSkew = TimeSpan.FromSeconds(0)  // if you immediately refresh the page after the app starts, you will get 401
                };
            });
    }
}
```

Note that for Id token, it is a little bit different, because when Client handles `https://localhost:7184/signin-oidc` which does the back-channel communication with idp to get id token and access token. Since the returned id token is immediately validated to generate the `ClaimsIdentity` which will be baked into cookie, so there is no point to set ClockSkew like:

```c#
public static class Config  // IDP
{
    // ...
    public static IEnumerable<Client> Clients =>
        new Client[]
        {
             new Client()
             {
                 IdentityTokenLifetime = 3 
             }
        }
}


public class Program  // Client
{
    public static void Main(string[] args)
    {
        // ...
        builder.Services.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                // ...
                ClockSkew = TimeSpan.FromSeconds(0)
            };
        });
    }
}
```

If you refresh the page, you will still remain as signin (note that the browser won't refresh with `https://localhost:5001/connect/authorize` url), because it takes less than a second for the back-channel communication from client to idp, so there is always a `ClaimsIdentity` created based on the id token (pass validation), then the next request when you refresh the page, the cookie contains the `ClaimsIdentity` will be used, the id token is not needed to be validate again.  If you want to break the authentication process :(  by setting `IdentityTokenLifetime = 0` in idp, you will get "unauthorized_client" error when you start the app, which make senses, the id token is not even valid (because the exp is the same as DateTime.Now when the id token is created) after it is returned by idp for client to validate.


If you turn on `options.UseTokenLifetime` as below: 

```C#
public class Program  // Client
{
    public static void Main(string[] args)
    {
        // ...
        builder.Services.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                // ...
                ClockSkew = TimeSpan.FromSeconds(0)
            };

            options.UseTokenLifetime = true;  // <---------------make client to generate user-client cookie with expiration time to be the same as IdentityTokenLifetime
        });
    }
}
```
and if you refresh the page, you will still be signin, and this time you will see the browser refresh with `https://localhost:5001/connect/authorize` url every 3 seconds
behind the scene, every time you refresh the page, it triggers a request of `https://localhost:5001/connect/authorize`, since user still remain login with idp (only user-to-client cookie expires), then idp does the same process as before and return id token and access token to client via backchannel then client forwards those tokens to user


**Refresh Token** (a reference typed token, not JWT type token, e.g `5074EFBCAE346907E56AF97FF481CEAE9E97864365F6E8A67C39A22416E34035-1`) only get generated when users requests with"offline_access" scope with idp's setting being `AllowOfflineAccess = true`  (check ofa flag). When you use a refresh token to generate a new access token, the lifespan or Time To Live (TTL) of the refresh token **remains the same** as specified in the initial OAuth flow (`AbsoluteRefreshTokenLifetime`), and the new access token has a new TTL of `AccessTokenLifetime`.

The reason why Refresh Token is associated with offline access is that when user-to-idp cookies expires, users normally have to be redirect to the idp's login page to enter credentials again. With refresh token, user doesn't need to login in idp again.

If you make user-to-idp cookie expires very quick as:

```C#
// idp
builder.Services.AddIdentityServer(options =>
{ 
    options.Authentication.CookieLifetime = TimeSpan.FromSeconds(5);
    options.Authentication.CookieSlidingExpiration = false;
})
```

then client can send a request with Refresh Token to idp so idp can return client with a new access token, id token, and new refresh token as well. Below is an implementation to allow this offline feature:

```C#
public class BearerTokenHandler : DelegatingHandler  // this is roughly what AddUserAccessTokenHandler does
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IHttpClientFactory _httpClientFactory;

    public BearerTokenHandler(IHttpContextAccessor httpContextAccessor, IHttpClientFactory httpClientFactory)
    {
        _httpContextAccessor = httpContextAccessor ?? throw new ArgumentNullException(nameof(httpContextAccessor));
        _httpClientFactory = httpClientFactory ?? throw new ArgumentNullException(nameof(httpClientFactory));
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var accessToken = await GetAccessTokenAsync();

        if (!string.IsNullOrWhiteSpace(accessToken))
        {
            request.SetBearerToken(accessToken);
        }

        return await base.SendAsync(request, cancellationToken);
    }

    public async Task<string> GetAccessTokenAsync()
    {
        // get the expires_at value & parse it
        var expiresAt = await _httpContextAccessor.HttpContext.GetTokenAsync("expires_at");

        var expiresAtAsDateTimeOffset = DateTimeOffset.Parse(expiresAt, CultureInfo.InvariantCulture);

        if ((expiresAtAsDateTimeOffset.AddSeconds(-60)).ToUniversalTime() > DateTime.UtcNow)
        {
            // no need to refresh, return the access token
            return await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.AccessToken);
        }

        var idpClient = _httpClientFactory.CreateClient("IDPClient");

        // get the discovery document
        var discoveryReponse = await idpClient.GetDiscoveryDocumentAsync();

        // refresh the tokens
        var refreshToken = await _httpContextAccessor.HttpContext.GetTokenAsync(OpenIdConnectParameterNames.RefreshToken);

        var refreshResponse = await idpClient.RequestRefreshTokenAsync(
            new RefreshTokenRequest
            {
                Address = discoveryReponse.TokenEndpoint,
                ClientId = "imagegalleryclient",
                ClientSecret = "secret",
                RefreshToken = refreshToken
            });

        // store the tokens             
        var updatedTokens = new List<AuthenticationToken>();
        updatedTokens.Add(new AuthenticationToken
        {
            Name = OpenIdConnectParameterNames.IdToken,
            Value = refreshResponse.IdentityToken
        });
        updatedTokens.Add(new AuthenticationToken
        {
            Name = OpenIdConnectParameterNames.AccessToken,
            Value = refreshResponse.AccessToken
        });
        updatedTokens.Add(new AuthenticationToken
        {
            Name = OpenIdConnectParameterNames.RefreshToken,
            Value = refreshResponse.RefreshToken
        });
        updatedTokens.Add(new AuthenticationToken
        {
            Name = "expires_at",
            Value = (DateTime.UtcNow + TimeSpan.FromSeconds(refreshResponse.ExpiresIn)).
                    ToString("o", CultureInfo.InvariantCulture)
        });

        // get authenticate result, containing the current principal &  properties
        var currentAuthenticateResult = await _httpContextAccessor.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

        // store the updated tokens
        currentAuthenticateResult.Properties.StoreTokens(updatedTokens);

        // sign in
        await _httpContextAccessor.HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            currentAuthenticateResult.Principal,
            currentAuthenticateResult.Properties);

        return refreshResponse.AccessToken;
    }
}
```

note that this "offline feature" implementation check whether an access token is expired/about to expire **before** sending the request with access token to Api, it is **not** something like send request with expired access token to Api first then retry

Access token can also be reference-type token, check `itp` flag to see how introspection process works. The benifits of access tokens being reference-type is, we can much control on its lifetime (the cost is client have to communicate with idp each time because the nature of reference-type tokens ) compared to jtw type (self-contained) of access token we don't have control on its lifetime, but the benefits of jwt type access token, we don't need to communicate with idp when validting tokens (of course, initial requests from `HttpDocumentRetriever` are needed to get jwks etc, but after that no need to communicate with idp anymore)

To use referenced-type jwt, `AddJwtBearer` cannot be used anymore:

```C#
// ClientProgram.cs
 builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
//.AddJwtBearer(options =>
//{
//    options.Authority = "https://localhost:5001";
//    options.Audience = "imagegalleryapi";  // <----------to validate whether the passed access token contains "aud" claim whose value should be "imagegalleryapi"
//    options.TokenValidationParameters = new TokenValidationParameters()
//    {
//        NameClaimType = "given_name",
//        RoleClaimType = "role",
//        ValidTypes = new[] { "at+jwt" },  // quite new setting, to avoid arbitary token with HMAC attack, no need to know in details                

//        ClockSkew = TimeSpan.FromSeconds(0)
//    };
//});
.AddOAuth2Introspection(options =>  // call idp's /connect/introspect 
{
    options.Authority = "https://localhost:5001";
    options.ClientId = "imagegalleryapi";
    options.ClientSecret = "apisecret";
    options.NameClaimType = "given_name";
    options.RoleClaimType = "role";
});
```

```C#
// idp
public static IEnumerable<Client> Clients =>
    new Client[] 
        {
            new Client()
            {
                ClientName = "Image Gallery",
                ClientId = "imagegalleryclient",
                AccessTokenType = AccessTokenType.Reference,  // <------------------------------change it to Refrence type, default is AccessTokenType.Jwt
                // ...
            }
        };
```


## Generating a Token with `dotnet user-jwts`

```c#
dotnet user-jwts create [options]
/*
  -n|--name     The name of the user to create the JWT for. Defaults to the current environment user.
  --audience    The audiences to create the JWT for. Defaults to the URLs configured in the project's launchSettings.json.
  --issuer      The issuer of the JWT. Defaults to 'dotnet-user-jwts'.
  --scope       A scope claim to add to the JWT. Specify once for each scope.
  --role        A role claim to add to the JWT. Specify once for each role.
  --claim       Claims to add to the JWT. Specify once for each claim in the format "name=value".
  --not-before  The UTC date & time the JWT should not be valid before in the format 'yyyy-MM-dd [[HH:mm[[:ss]]]]'. Defaults to the date & time the JWT is created.
  --expires-on
*/


dotnet user-jwts create -n "b7539694-97e7-4dfe-84da-b4256e1ff5c7"
/*
{
  "unique_name": "b7539694-97e7-4dfe-84da-b4256e1ff5c7",
  "sub": "b7539694-97e7-4dfe-84da-b4256e1ff5c7",
  "jti": "a179ba9",
  "aud": [
    "http://localhost:17302",
    "https://localhost:44324",
    "https://localhost:7075",
    "http://localhost:5075"
  ],
  "nbf": 1723990414,
  "exp": 1731939214,
  "iat": 1723990415,
  "iss": "dotnet-user-jwts"
}
Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6ImI3NTM5Njk0LTk3ZTctNGRmZS04NGRhLWI0MjU2ZTFmZjVjNyIsInN1YiI6ImI3NTM5Njk0LTk3ZTctNGRmZS04NGRhLWI0MjU2ZTFmZjVjNyIsImp0aSI6ImExNzliYTkiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDoxNzMwMiIsImh0dHBzOi8vbG9jYWxob3N0OjQ0MzI0IiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NzA3NSIsImh0dHA6Ly9sb2NhbGhvc3Q6NTA3NSJdLCJuYmYiOjE3MjM5OTA0MTQsImV4cCI6MTczMTkzOTIxNCwiaWF0IjoxNzIzOTkwNDE1LCJpc3MiOiJkb3RuZXQtdXNlci1qd3RzIn0.wjNVilLX7r-RGgfdg7SbTzGo4usz2WkamRIjt9I9OjE
*/
```

when you create a local jwt using `dotnet user-jwts create`, following changes are added automatically:

```json 
//appsetting.Development.json, you also need to comment out all option settings in `AddJwtBearer`
// ...
"Authentication": {
    "Schemes": {
      "Bearer": {
        "ValidAudiences": [
          "http://localhost:17302",
          "https://localhost:44324",
          "https://localhost:7075",
          "http://localhost:5075"
        ],
        "ValidIssuer": "dotnet-user-jwts"
      }
    }
  }
```

```xml
<PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <WarningLevel>0</WarningLevel>
    <UserSecretsId>8xxx-xxx-xxx-xxx-xxxxxxxx</UserSecretsId>
</PropertyGroup>
```

```C#
// %APPDATA%\Microsoft\UserSecrets\<secrets_GUID>\secrets.json
{
    "Authentication:Schemes:Bearer:SigningKeys": [
        {
            "Id": "92dcc84b",
            "Issuer": "dotnet-user-jwts",
            "Value": "evIxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "Length": 32
        }
    ]
}

// %APPDATA%\Microsoft\UserSecrets\<secrets_GUID>\user-jwts.json
{
    "a179ba9": {
        "Id": "a179ba9",
        "Scheme": "Bearer",
        "Name": "b7539694-97e7-4dfe-84da-b4256e1ff5c7",
        "Audience": "http://localhost:17302, https://localhost:44324, https://localhost:7075, http://localhost:5075",
        "NotBefore": "2024-08-18T14:13:34+00:00",
        "Expires": "2024-11-18T14:13:34+00:00",
        "Issued": "2024-08-18T14:13:35+00:00",
        "Token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1bmlxdWVfbmFtZSI6ImI3NTM5Njk0LTk3ZTctNGRmZS04NGRhLWI0MjU2ZTFmZjVjNyIsInN1YiI6ImI3NTM5Njk0LTk3ZTctNGRmZS04NGRhLWI0MjU2ZTFmZjVjNyIsImp0aSI6ImExNzliYTkiLCJhdWQiOlsiaHR0cDovL2xvY2FsaG9zdDoxNzMwMiIsImh0dHBzOi8vbG9jYWxob3N0OjQ0MzI0IiwiaHR0cHM6Ly9sb2NhbGhvc3Q6NzA3NSIsImh0dHA6Ly9sb2NhbGhvc3Q6NTA3NSJdLCJuYmYiOjE3MjM5OTA0MTQsImV4cCI6MTczMTkzOTIxNCwiaWF0IjoxNzIzOTkwNDE1LCJpc3MiOiJkb3RuZXQtdXNlci1qd3RzIn0.wjNVilLX7r-RGgfdg7SbTzGo4usz2WkamRIjt9I9OjE",
        "Scopes": [],
        "Roles": [],
        "CustomClaims": {}
    }
}
```
=========================================================================
Before `JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear()`  (check jcm flag)

```C#
/*
Claim type: http://schemas.microsoft.com/claims/authnmethodsreferences - Claim value: pwd
Claim type: sid - Claim value: B0CD6BD2B433776A782B8DA1D17ED4AA
Claim type: http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier - Claim value: b7539694-97e7-4dfe-84da-b4256e1ff5c7
Claim type: auth_time - Claim value: 1722512787
Claim type: http://schemas.microsoft.com/identity/claims/identityprovider - Claim value: local
Claim type: given_name - Claim value: Emma
Claim type: family_name - Claim value: Flagg
*/
```

After `JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear()`

```C#
/*
Claim type: amr - Claim value: pwd
Claim type: sid - Claim value: 8E4BE37574693434DB7CE9FBA0CF616B
Claim type: sub - Claim value: b7539694-97e7-4dfe-84da-b4256e1ff5c7
Claim type: auth_time - Claim value: 1722513034
Claim type: idp - Claim value: local
Claim type: given_name - Claim value: Emma
Claim type: family_name - Claim value: Flagg
*/
```

by default, `JsonWebTokenHandler.DefaultInboundClaimTypeMap` maps claims in jwt to microsoft's "soap" alike claim type, since we call `Clear()` to remove the mapping, we can get the "shorter" jwt alike claim

================================================================================

Why `@if (User.IsInRole("PayingUser"))` might not work, there is why:

```C#
.AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
{
    options.TokenValidationParameters = new TokenValidationParameters()  // <---------------cci
    {
        NameClaimType = "give_name",
        RoleClaimType = "role"
    };
});

public class ClaimsPrincipal
{
    public virtual bool IsInRole(string role)
    {
        for (int i = 0; i < _identities.Count; i++)
        {
            if (_identities[i] != null)
            {
                if (_identities[i].HasClaim(_identities[i].RoleClaimType, role))  // RoleClaimType is different when TokenValidationParameters is set
                {
                    return true;
                }
            }
        }

        return false;
    }
}

/*  for the ClaimIdentity

Before TokenValidationParameters setting:
    RoleClaimType is http://schemas.microsoft.com/ws/2008/06/identity/claims/role
    NameClaimType is http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name

After TokenValidationParameters setting:
    RoleClaimType is "role"
    NameClaimType is "give_name"

which affect the usage on the Razor Page 

@if (User.IsInRole("PayingUser"))  // is false even though user is PayingUser if we don't setup TokenValidationParameters in cci
{
    <li class="nav-item">
        <a class="nav-link text-dark" asp-area="" asp-controller="Gallery" asp-action="AddImage">Add an Image</a>
    </li>
}   
*/
```
==========================================================================================

Final Tokens:

**access token**:

```json
{
  "alg": "RS256",
  "kid": "7AB6CB1B3C3DAA763A562E4AEFED9E42",
  "typ": "at+jwt"
}

{
  "iss": "https://localhost:5001",
  "nbf": 1722867025,
  "iat": 1722867025,
  "exp": 1722870625,
  "aud": [
    "imagegalleryapi",
    "https://localhost:5001/resources"   // <-------------idp is in the audience claim because clientApp needs to pass access token to idp to call UserInfo endpoint, and 
                                         // idp needs to verify this access token, that's why idp is also an audience of this token
  ],
  "scope": [
    "openid",
    "profile",
    "imagegalleryapi.fullaccess",
    "roles"
  ],
  "amr": [
    "pwd"
  ],
  "client_id": "imagegalleryclient",
  "sub": "b7539694-97e7-4dfe-84da-b4256e1ff5c7",
  "auth_time": 1722866757,
  "idp": "local",
  "role": "PayingUser",   // <---------------because of the config: new ApiResource("imagegalleryapi", "Image Gallery API", new [] { "role" }) 
  "sid": "ECD46FC90D6FDB3DEDAE3C5C4E0B4471",
  "jti": "C1EAB2F678AD8754945E89EC970129DD"
}
```

**id token**:

```json
{
  "alg": "RS256",
  "kid": "7AB6CB1B3C3DAA763A562E4AEFED9E42",
  "typ": "JWT"
}

{
  "iss": "https://localhost:5001",
  "nbf": 1722867025,
  "iat": 1722867025,
  "exp": 1722867325,
  "aud": "imagegalleryclient",
  "amr": [
    "pwd"
  ],
  "nonce": "638584638230545591.NDc5MGNjY2QtYmM2NC00ODdlLTk3NzQtZTE5MGZhNGY1MGJkZGU2MThiMmQtYzRkYi00N2EwLWEwZTAtZmQ1NTcwODY3YjYy",
  "at_hash": "AKRurD4s-cFVucp4AdaBlg",
  "sid": "ECD46FC90D6FDB3DEDAE3C5C4E0B4471",
  "sub": "b7539694-97e7-4dfe-84da-b4256e1ff5c7",
  "auth_time": 1722866757,
  "idp": "local"
}
```


==========================================================================================


```C#
public abstract class Resource
{
    public bool Enabled { get; set; } = true;
    public string Name { get; set; } = default!;
    public string? DisplayName { get; set; }
    public string? Description { get; set; }
    public bool ShowInDiscoveryDocument { get; set; } = true;
    public ICollection<string> UserClaims { get; set; } = new HashSet<string>();
    public IDictionary<string, string> Properties { get; set; } = new Dictionary<string, string>();
}
```

`Scope` is kind of a role to access a specific set of resources. IdentityServer has two scope types: 

* **Identity Scope** : representing identity data (e.g. profile or email), goes to **id token**

```C#
public class IdentityResource : Resource
{
    public IdentityResource() { }

    public IdentityResource(string name, IEnumerable<string> userClaims) : this(name, name, userClaims) { }

    public IdentityResource(string name, string displayName, IEnumerable<string> userClaims)
    {
        Name = name;
        DisplayName = displayName;

        foreach(var type in userClaims)
        {
            UserClaims.Add(type);
        }      
    }

    public bool Required { get; set; } = false;
    public bool Emphasize { get; set; } = false;
}

public class OpenId : IdentityResource
{
    public OpenId()
    {
        Name = IdentityServerConstants.StandardScopes.OpenId;  // "openid"
        DisplayName = "Your user identifier";
        Required = true;
        UserClaims.Add(JwtClaimTypes.Subject);
    }
}

public class Profile : IdentityResource
{
    public Profile()
    {
        Name = IdentityServerConstants.StandardScopes.Profile;  // "profile"
        DisplayName = "User profile";
        Description = "Your user profile information (first name, last name, etc.)";
        Emphasize = true;
        UserClaims = Constants.ScopeToClaimsMapping[IdentityServerConstants.StandardScopes.Profile].ToList();
    }
}
```

* **Resource Scope** : representing a resource (e.g. a web api), goes to **access token**

```C#
public class ApiScope : Resource
{
    public ApiScope() { }
    public ApiScope(string name) : this(name, name, null) { }
    public ApiScope(string name, string displayName) : this(name, displayName, null) { }
    public ApiScope(string name, IEnumerable<string> userClaims) : this(name, name, userClaims) { }
    public ApiScope(string name, string displayName, IEnumerable<string>? userClaims)
    {
        Name = name;
        DisplayName = displayName;

        if (!userClaims.IsNullOrEmpty())
        {
            foreach (var type in userClaims!)
            {
                UserClaims.Add(type);
            }
        }
    }

    public bool Required { get; set; } = false;
    public bool Emphasize { get; set; } = false;
}
```

ApiResource

```C#
public class ApiResource : Resource
{
    public ApiResource() { }
    public ApiResource(string name) : this(name, name, null) { }
    public ApiResource(string name, string displayName) : this(name, displayName, null) { }
    public ApiResource(string name, IEnumerable<string> userClaims) : this(name, name, userClaims) { }

    public ApiResource(string name, string displayName, IEnumerable<string> userClaims)
    {
        Name = name;
        DisplayName = displayName;

        if (!userClaims.IsNullOrEmpty())
        {
            foreach (var type in userClaims)
            {
                UserClaims.Add(type);
            }
        }
    }

    public ICollection<Secret> ApiSecrets { get; set; } = new HashSet<Secret>();
    public ICollection<string> Scopes { get; set; } = new HashSet<string>();
    public ICollection<string> AllowedAccessTokenSigningAlgorithms { get; set; } = new HashSet<string>();
}
```

===================================================================================================================================


## Integration with Third-Party Identity Provider

let's integrate identity server with Facebook. This time, our IDP (Marvin.IDP) becomes "Client",  Facebook is the "IDP"

```C#
//-------------------------------------------V idp
builder.Services.AddIdentityServer(options =>   // <----------------------calls AddCookieAuthentication()
{
    // ...
})

builder.Services.AddAuthentication().AddFacebook("Facebook", options =>
{
        options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;  // <-------------------itp0
        options.AppId = "123456789";
        options.AppSecret = "ff5bexxxxx";
});
//-------------------------------------------Ʌ


//-------------------------------------------V
// Pages/Account/Login/Index.cshtml
@if (Model.View.VisibleExternalProviders.Any())
{
    <div class="col-sm-6">
        <div class="card">
            <div class="card-header">
                <h2>External Account</h2>
            </div>
            <div class="card-body">
                <ul class="list-inline">
                    @foreach (var provider in Model.View.VisibleExternalProviders)
                    {
                        <a class="btn btn-secondary"
                            asp-page="/ExternalLogin/Challenge"    // <-------------------itp1.0
                            asp-route-scheme="@provider.AuthenticationScheme"
                            asp-route-returnUrl="@Model.Input.ReturnUrl">
                            @provider.DisplayName
                        </a>
                    }
                </ul>
            </div>
        </div>
    </div>
}
//-------------------------------------------Ʌ

//-------------------------------------V Pages/ExternalLogin/Challenge.cshtml
public class Challenge : PageModel
{
    private readonly IIdentityServerInteractionService _interactionService;

    public Challenge(IIdentityServerInteractionService interactionService)
    {
        _interactionService = interactionService;
    }
        
    public IActionResult OnGet(string scheme, string? returnUrl)   // returnUrl is /connect/authorize/callback?client_id=imagegalleryclient&redirect_uri=https
    {
        if (string.IsNullOrEmpty(returnUrl)) returnUrl = "~/";

        // validate returnUrl - either it is a valid OIDC URL or back to a local page
        if (Url.IsLocalUrl(returnUrl) == false && _interactionService.IsValidReturnUrl(returnUrl) == false)
        {
            // user might have clicked on a malicious link - should be logged
            throw new ArgumentException("invalid return URL");
        }
            
        // start challenge and roundtrip the return URL and scheme 
        var props = new AuthenticationProperties
        {
            RedirectUri = Url.Page("/externallogin/callback"),  // <------------like ExternalSignInModel.OnGetCorrelate
                
            Items =
            {
                { "returnUrl", returnUrl }, 
                { "scheme", scheme },
            }
        };

        return Challenge(props, scheme);   // <-------------------itp1.1. Behind the scene, ChallengeResult.ExecuteResultAsync() which internally calls httpContext.ChallengeAsync(...);
                                           // jump to FacebookHandler -> OAuthHandler.HandleChallengeAsync for reference
    }
}
//-------------------------------------Ʌ

//------------------------------------V Pages/ExternalLogin/Callback.cshtml
public class Callback : PageModel
{
    //private readonly TestUserStore _users;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly ILogger<Callback> _logger;
    private readonly IEventService _events;

    public Callback(
        IIdentityServerInteractionService interaction,
        IEventService events,
        ILogger<Callback> logger)
    {
        // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)
        // _users = users ?? throw new InvalidOperationException("Please call 'AddTestUsers(TestUsers.Users)' on the IIdentityServerBuilder in Startup or remove the TestUserStore from the AccountController.");

        _interaction = interaction;
        _logger = logger;
        _events = events;
    }
        
    public async Task<IActionResult> OnGet()
    {
        // read external identity from the temporary cookie
        var result = await HttpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
        if (result.Succeeded != true)
        {
            throw new InvalidOperationException($"External authentication error: { result.Failure }");
        }

        var externalUser = result.Principal ?? 
            throw new InvalidOperationException("External authentication produced a null Principal");
		
        if (_logger.IsEnabled(LogLevel.Debug))
        {
            var externalClaims = externalUser.Claims.Select(c => $"{c.Type}: {c.Value}");
            _logger.ExternalClaims(externalClaims);
        }

        // lookup our user and external provider info
        // try to determine the unique id of the external user (issued by the provider)
        // the most common claim type for that are the sub claim and the NameIdentifier
        // depending on the external provider, some other claim type might be used
        var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                          externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                          throw new InvalidOperationException("Unknown userid");

        var provider = result.Properties.Items["scheme"] ?? throw new InvalidOperationException("Null scheme in authentiation properties");
        var providerUserId = userIdClaim.Value;

        /*
        // find external user
        var user = _users.FindByExternalProvider(provider, providerUserId);
        if (user == null)
        {
            // this might be where you might initiate a custom workflow for user registration
            // in this sample we don't show how that would be done, as our sample implementation
            // simply auto-provisions new external user
            //
            // remove the user id claim so we don't include it as an extra claim if/when we provision the user
            var claims = externalUser.Claims.ToList();
            claims.Remove(userIdClaim);
            user = _users.AutoProvisionUser(provider, providerUserId, claims.ToList());
        }
        */

        // this allows us to collect any additional claims or properties
        // for the specific protocols used and store them in the local auth cookie.
        // this is typically used to store data needed for signout from those protocols.
        var additionalLocalClaims = new List<Claim>();
        var localSignInProps = new AuthenticationProperties();
        CaptureExternalLoginContext(result, additionalLocalClaims, localSignInProps);
            
        // issue authentication cookie for user
        var isuser = new IdentityServerUser(providerUserId)
        {
            DisplayName = providerUserId,
            IdentityProvider = provider,
            AdditionalClaims = additionalLocalClaims
        };

        await HttpContext.SignInAsync(isuser, localSignInProps);

        // delete temporary cookie used during external authentication
        await HttpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

        // retrieve return URL
        var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

        // check if external login is in the context of an OIDC request
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        await _events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, providerUserId, providerUserId, true, context?.Client.ClientId));
        Telemetry.Metrics.UserLogin(context?.Client.ClientId, provider!);

        if (context != null)
        {
            if (context.IsNativeClient())
            {
                // The client is native, so this change in how to
                // return the response is for better UX for the end user.
                return this.LoadingPage(returnUrl);
            }
        }

        return Redirect(returnUrl);
    }

    // if the external login is OIDC-based, there are certain things we need to preserve to make logout work
    // this will be different for WS-Fed, SAML2p or other protocols
    private static void CaptureExternalLoginContext(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
    {
        ArgumentNullException.ThrowIfNull(externalResult.Principal, nameof(externalResult.Principal));

        // capture the idp used to login, so the session knows where the user came from
        localClaims.Add(new Claim(JwtClaimTypes.IdentityProvider, externalResult.Properties?.Items["scheme"] ?? "unknown identity provider"));

        // if the external system sent a session id claim, copy it over
        // so we can use it for single sign-out
        var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
        if (sid != null)
        {
            localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
        }

        // if the external provider issued an id_token, we'll keep it for signout
        var idToken = externalResult.Properties?.GetTokenValue("id_token");
        if (idToken != null)
        {
            localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });
        }
    }
}
//------------------------------------Ʌ
```

Let's see the difference between oidc flow and third-party integration flow

```C#
public abstract class RemoteAuthenticationHandler<TOptions> : AuthenticationHandler<TOptions>, IAuthenticationRequestHandler;

//-------------------------------V
public class OpenIdConnectHandler : RemoteAuthenticationHandler<OpenIdConnectOptions>, IAuthenticationSignOutHandler;
//-------------------------------Ʌ

//---------------------------------V
public class OAuthHandler<TOptions> : RemoteAuthenticationHandler<TOptions>;
public class FacebookHandler : OAuthHandler<FacebookOptions>
//---------------------------------Ʌ
```

=========================================================================================================================

## Full Sample Code

```C#
//--------------------------------V IdentityServer runs on https://localhost:5001
public class IdentityServerProgram
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddRazorPages();

        builder.Services.AddScoped<IPasswordHasher<Entities.User>, PasswordHasher<Entities.User>>();
        builder.Services.AddScoped<ILocalUserService, LocalUserService>();

        builder.Services.AddDbContext<IdentityDbContext>(options =>
        {
            options.UseSqlite(
                builder.Configuration.GetConnectionString("MarvinIdentityDBConnectionString"));
        });

        builder.Services.AddIdentityServer(options => 
        {
            options.EmitStaticAudienceClaim = true;

            //options.Authentication.CookieLifetime = TimeSpan.FromSeconds(5);
            //options.Authentication.CookieSlidingExpiration = false;
        })
        .AddInMemoryIdentityResources(Config.IdentityResources)
        .AddInMemoryApiScopes(Config.ApiScopes)
        .AddInMemoryClients(Config.Clients)
        //.AddTestUsers(TestUsers.Users);
        .AddProfileService<LocalUserProfileService>();

        var app = builder.Build();

        app.UseStaticFiles();

        app.UseRouting();

        app.UseIdentityServer();

        app.UseAuthorization();

        app.MapRazorPages().RequireAuthorization();

        app.Run();
    }
}

public static class Config  // we can say IdentityResource is for id token while ApiResource is for access token
{
    /* 
      public IdentityResource(string name, string displayName, IEnumerable<string> userClaims)
    */
    public static IEnumerable<IdentityResource> IdentityResources =>  // IdentityResource/s is used for idp's userinfo endpoint     
        new IdentityResource[]                                        // IdentityResource's Name will be scope name
        { 
            new IdentityResources.OpenId(),
            new IdentityResources.Profile(),
            new IdentityResource(
                "roles",  // <-------------"roles" scope, need to match AllowedScopes in Clients
                "Your role(s)",  
                new [] { "role" }), // <------means when user requires "roles" scope, idp needs to return "role" (in the string array) claim
                                    // but still id token won't contain this "role claim", it's idp's Userinfo endpoint returns userClaims (in JsonDocument fomat) like role claim (given that options.GetClaimsFromUserInfoEndpoint = true)
                                    // so that user-to-client cookie (AuthenticateTicket, reside on user's end) will contains role claims (pass to client via cookie)
           
            new IdentityResource(
                "country", 
                "The country you're living in",
                new [] { "country" })
        };      

    public static IEnumerable<ApiResource> ApiResources =>  // note that once one of the scope is "clicked" by user, the corresponding ApiResource.Name will be in the aud
        new ApiResource[]
        {
            new ApiResource("imagegalleryapi", "Image Gallery API", new [] { "role", "country" })  // role here results the access token to contains a role claim such as { "role" : "payinguser" }
            { 
                Scopes = { "imagegalleryapi.fullaccess", "imagegalleryapi.read", "imagegalleryapi.write" },   // public ICollection<string> Scopes { get; set; } = new HashSet<string>();
                ApiSecrets = { new Secret("apisecret".Sha256()) }
            },
            
            new ApiResource("OtherResource", "other resource")
            {
                Scopes = { "other.fullaccess" }
            },

            /*  ApiResource in audience claim list, API scope in scopes claim list, check idpaud flag to see how "aud" is generated
             {
               ...,
               "aud": [ 
                 "imagegalleryapi",      //*V we have two ApiResource in place, that's why there are two entities (actually three) in "aud"
                 "OtherResource",        //*Ʌ
                 "https://localhost:5001/resources" // the reason that the idp itself in also in the "aud" because access token is needed for client to call UserInfo endpoint
               ],                                   // which makes the idp itself is also an "consumer" of the access token, that's why idp is in the "aud"
               "scopes": [ 
                 "openid",
                 "profile",
                 "imagegalleryapi.fullaccess",
                 "other.fullaccess",
                 "roles"
               ]
             }
            */   
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new ApiScope[]
        {
            new ApiScope("imagegalleryapi.fullaccess"),
            new ApiScope("imagegalleryapi.read"),
            new ApiScope("imagegalleryapi.write"),
            new ApiScope("other.fullaccess"),
        };

    public static IEnumerable<Client> Clients => 
        new Client[] 
        {
            new Client()
            {
                ClientName = "Image Gallery",
                ClientId = "imagegalleryclient",
                AllowedGrantTypes = GrantTypes.Code,
                AccessTokenType = AccessTokenType.Reference,  // default is AccessTokenType.Jwt
                AllowOfflineAccess = true,
                UpdateAccessTokenClaimsOnRefresh = true,
                //RefreshTokenExpiration =  // default is TokenExpiration.Absolute (controlled by AbsoluteRefreshTokenLifetime), if change to TokenExpiration.Sliding, controlled by SlidingRefreshTokenLifetime
                //AbsoluteRefreshTokenLifetime = 12, // default is 30 days
                //SlidingRefreshTokenLifetime =  // default is 15 days, refer to https://github.com/IdentityServer/IdentityServer3/issues/2411#issuecomment-171483658
                //AuthoriztionCodeLifetime = ...
                //IdentityTokenLifetime = 3, // default is 5 mins
                AccessTokenLifetime = 3,   // default is 1 hour

                //UpdateAccessTokenClaimsOnRefresh = true,
                RedirectUris =
                {
                    "https://localhost:7184/signin-oidc"
                },
                PostLogoutRedirectUris =
                {
                    "https://localhost:7184/signout-callback-oidc"
                },
                AllowedScopes = 
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    "roles",
                    //"imagegalleryapi.fullaccess",
                    "imagegalleryapi.read",
                    "imagegalleryapi.write",
                    "country",
                    "other.fullaccess",
                    "non-exist"  // it is ok, won't throw exception, which means that AllowedScopes doesn't control what scopes to be displayed to client
                },
                ClientSecrets =
                {
                    new Secret("secret".Sha256())
                },
                RequireConsent = true
            }
        };
}
//--------------------------------Ʌ dentityServer
```

```C#
//------------------------V Client(RP) runs on https://localhost:7184
public class ClientProgram 
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // Add services to the container.
        builder.Services.AddControllersWithViews()
            .AddJsonOptions(configure =>
                configure.JsonSerializerOptions.PropertyNamingPolicy = null);

        builder.Services.AddAccessTokenManagement();  // from IdentityModel.AspNetCore, so that you don't need to write custom DelegatingHandler to pass access token in named HttpClient

        //--------------------------------------------------------------V
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddTransient<BearerTokenHandler>();

        builder.Services.AddHttpClient("IDPClient", client =>
        {
            client.BaseAddress = new Uri("https://localhost:5001/");
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
        });

        // create an HttpClient used for accessing the API
        builder.Services.AddHttpClient("APIClient", client =>
        {
            client.BaseAddress = new Uri(builder.Configuration["ImageGalleryAPIRoot"]);   // Api https://localhost:7075
            client.DefaultRequestHeaders.Clear();
            client.DefaultRequestHeaders.Add(HeaderNames.Accept, "application/json");
        })
        //.AddHttpMessageHandler<BearerTokenHandler>();
        .AddUserAccessTokenHandler();
        // third party DelegatingHandlerlike BearerTokenHandler to pass access token via HTTP request in APIClient, so you don't need to write one
        // note that access token is retrieved from AuthenticationTicket.AuthenticationProperties, check o4.3 flag, that's why AddCookie is needed
        // also note that AddUserAccessTokenHandler() also automatically refresh access token when it is about to expire or when it has expired, it is like BearerTokenHandler 
        // if you wonder how AddUserAccessTokenHandler knows the address of idp, it is from DefaultTokenClientConfigurationService which uses OpenIdConnectOptions.ConfigurationManager
        // https://github.com/IdentityModel/IdentityModel.AspNetCore/blob/72479bf781eac07b5f7f568ae45e498b5ba9ed69/src/AccessTokenManagement/DefaultTokenClientConfigurationService.cs#L186
        //--------------------------------------------------------------Ʌ

        JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();  // check jcm flag

        builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
        {
            options.AccessDeniedPath = "/Authentication/AccessDenied";
        })
        .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.Authority = "https://localhost:5001/";
            options.ClientId = "imagegalleryclient";
            options.ClientSecret = "secret";
            options.ResponseType = "code";
            
            //----------------------------->> used by default
            //options.Scope.Add("openid");   
            //options.Scope.Add("profile");
            //options.CallbackPath = new PathString("signin-oidc");
            //-----------------------------<<

            // SignedOutCallbackPath must match with PostLogoutRedirectUris at IDP client config
            // if you want to automatically return to the application after logging out of IdentityServer.
            //options.SignedOutCallbackPath = new PathString("signout-callback-oidc");  // default

            options.SaveTokens = true;
            options.GetClaimsFromUserInfoEndpoint = true;  // o4.6 in OpenIdConnectHandler, this is the prerequisite for options.ClaimActions.MapJsonKey("role", "role") below

            // this is to ask to include aud claim, the name is confusing, you call Remove to include something but it is what it is,
            // bechind the scene, "Remove" removes the filter DeleteClaimAction, check oica flag in OpenIdConnectOptions
            options.ClaimActions.Remove("aud");

            options.ClaimActions.DeleteClaim("sid");
            options.ClaimActions.DeleteClaim("idp");

            //----------------------------------------------V add a Role scope 
            options.Scope.Add("roles");
            /* public static void MapJsonKey(this ClaimActionCollection collection, string claimType, string jsonKey)
               check mjku flag you'll see why it is needed when GetClaimsFromUserInfoEndpoint is set to true
               because UserInfo endpoint on IDP will return user info as JsonDocument
            */
            options.ClaimActions.MapJsonKey("role", "role");
            //----------------------------------------------Ʌ

            //options.Scope.Add("imagegalleryapi.fullaccess"); // when this scope is requested by user, idp will locate the ApiResource name (imagegalleryapi)
                                                             // this scope, so the generated access token will contain a token that contains "aud": [ "imagegalleryapi" ]
            options.Scope.Add("imagegalleryapi.read");
            options.Scope.Add("imagegalleryapi.write");

            options.Scope.Add("country");
            options.Scope.Add("offline_access");
            options.ClaimActions.MapUniqueJsonKey("country", "country");

            options.Scope.Add("other.fullaccess");

            // it will affect how JsonWebTokenHandler generate ClaimsIdentity, epsecially on ClaimsIdentity.RoleClaimTypethis
            options.TokenValidationParameters = new TokenValidationParameters()
            {
                NameClaimType = "give_name",
                RoleClaimType = "role",  // set ClaimsIdentity.RoleClaimTypethis setting. It is requred as it affect `User.IsInRole("PayingUser")` in the view model

                ClockSkew = TimeSpan.FromSeconds(0)
            };
            options.UseTokenLifetime = true;  // only assoicate with idp's IdentityTokenLifetime
        });

        // ...

        var app = builder.Build();

        app.UseStaticFiles();

        app.UseRouting();

        app.UseAuthentication();

        app.UseAuthorization();

        app.MapControllerRoute(name: "default", pattern: "{controller=Gallery}/{action=Index}/{id?}");
        
        app.Run();
    }
}
//------------------------Ʌ Client
```

```C#
//----------------------V Api
public class ApiProgram  // Api runs on https://localhost:7075
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddControllers();
        // ...

        JsonWebTokenHandler.DefaultInboundClaimTypeMap.Clear();  // check jcm flag

        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)  // <--------------------------
            .AddJwtBearer(options =>
            {
                options.Authority = "https://localhost:5001";
                options.Audience = "imagegalleryapi";  // <----------to validate whether the passed access token contains "aud" claim whose value should be "imagegalleryapi"
                options.TokenValidationParameters = new TokenValidationParameters()
                {
                    NameClaimType = "given_name",
                    RoleClaimType = "role",
                    ValidTypes = new[] { "at+jwt" },  // quite new setting, to avoid arbitary token with HMAC attack, no need to know in details                

                    ClockSkew = TimeSpan.FromSeconds(0)
                };
            });

        builder.Services.AddAuthorization(opts =>
        {
            opts.AddPolicy("ClientApplicationCanWrite", policyBuilder =>
            {
                policyBuilder.RequireClaim("scope", "imagegalleryapi.write");
            });
            // ...
        });

        var app = builder.Build();

        app.UseHttpsRedirection();

        app.UseStaticFiles();

        app.UseAuthentication();

        app.UseAuthorization();

        app.MapControllers();

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
           "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjhFNjFCRTk2NEFCQUM5NkVEMDU2RDQ5M0RCODQ3M0E2IiwidHlwIjoiYXQrand0In0.eyJpcMiOiJodHRwczovL2xvY2FsaG9zdDo1MDAxIiwibmJmIjoxNzIwNjE5MjczLCJpYXQiOjE3MjA2MTkyNzMsImV4cCI6MTcyMDYyMjg3Mywic2NvcGUiOlsiYXBpMSJdLCJjbGllbnRfaWQiOiJjbGllbnQiLCJqdGkiOiI4NTBEODIzNUFCRTVERkQwQTJFOTE3MjEyODFDNzE1QyJ9.TPF3XuEpz-HgkIAxpsXKzRBZcyALNiQsK_cCBYHV-qrEiND0zZm7wffqUEXr3OeCNU0uiF06Fs3IBAGcNW6nLCp7vHDi-zCidqD8hTGg1tUCxOzDttltzcDF7CyvK81ZaJUb-KOz1Pivi8GfmKcFeV8hK_UfFSPjqh8BAQtQlbyJCdK2eYFbML3lcujzFDtitP4v5kpq3B6m_cx9xnOQ3fUK2Q8ve7f7DZgWLM51dwkyu11nWliRRcZQBsu5GT9EhmqTiB69y8PsV6mAYbhSb5BKN0YelV2RU5G89wVYoxQPYvNUP5TDOdI-XEgRX2mKYMKy_Ilf60q_KkqAGgilHQ",
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

```C#
//--------------------------------V
public interface ILocalUserService
{
    Task<bool> ValidateCredentialsAsync(string userName, string password);
    Task<IEnumerable<UserClaim>> GetUserClaimsBySubjectAsync(string subject);
    Task<User> GetUserByUserNameAsync(string userName);
    Task<User> GetUserBySubjectAsync(string subject);
    void AddUser(User userToAdd, string password);
    Task<bool> ActivateUserAsync(string securityCode);
    Task<bool> IsUserActive(string subject);
    Task<bool> SaveChangesAsync();
}

public class LocalUserService : ILocalUserService
{
    private readonly IdentityDbContext _context;
    private readonly IPasswordHasher<User> _passwordHasher;

    public LocalUserService(
        IdentityDbContext context,
        IPasswordHasher<User> passwordHasher)
    {
        _context = context ?? throw new ArgumentNullException(nameof(context));
        _passwordHasher = passwordHasher ?? throw new ArgumentNullException(nameof(passwordHasher));
    }


    public async Task<bool> IsUserActive(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            return false;
        }

        var user = await GetUserBySubjectAsync(subject);

        if (user == null)
        {
            return false;
        }

        return user.Active;
    }

    public async Task<bool> ValidateCredentialsAsync(string userName,
      string password)
    {
        if (string.IsNullOrWhiteSpace(userName) ||
            string.IsNullOrWhiteSpace(password))
        {
            return false;
        }

        var user = await GetUserByUserNameAsync(userName);

        if (user == null)
        {
            return false;
        }

        if (!user.Active)
        {
            return false;
        }

        // Validate credentials
        // return (user.Password == password);

        /*
          note that the default implementation does not use the `user` parameter. That is because users can be represented differently in various systems.
          however, in custom implementations of the IPasswordHasher<TUser> interface, user details could be incorporated into the hashing process.
        */
        var verificationResult = 
            _passwordHasher.VerifyHashedPassword(user, user.Password, password);// user.Password is the hash password store in database, password is the provided password
                                                                                //passwordHasher needs it  to retrieve salt which is noramlly appended to the hash password

        /* prerequsite: salt, salt is randomly generated for each user appended to the hashed password

           UserA:

           Password: farm1990M0O

           Salt: f1nd1ngn3m0

           Salted input: farm1990M0Of1nd1ngn3m0

           Hash (SHA-256): 07dbb6e6832da0841dd79701200e4b179f1a94a7b3dd26f612817f3c03117434f1nd1ngn3m0

           UserB:

           Password: farm1990M0O

           Salt: f1nd1ngd0ry

           Salted input: farm1990M0Of1nd1ngd0ry

           Hash (SHA-256): 11c150eb6c1b776f390be60a0a5933a2a2f8c0a0ce766ed92fea5bfd9313c8f6f1nd1ngd0ry

           * Note that UserA and UserB use same password but hashed password are still different
        */

        return (verificationResult == PasswordVerificationResult.Success);
    }


    public async Task<User> GetUserByUserNameAsync(string userName)
    {
        if (string.IsNullOrWhiteSpace(userName))
        {
            throw new ArgumentNullException(nameof(userName));
        }

        return await _context.Users
             .FirstOrDefaultAsync(u => u.UserName == userName);
    }

    public async Task<IEnumerable<UserClaim>> GetUserClaimsBySubjectAsync(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new ArgumentNullException(nameof(subject));
        }

        return await _context.UserClaims.Where(u => u.User.Subject == subject).ToListAsync();
    }

    public async Task<User> GetUserBySubjectAsync(string subject)
    {
        if (string.IsNullOrWhiteSpace(subject))
        {
            throw new ArgumentNullException(nameof(subject));
        }

        return await _context.Users.FirstOrDefaultAsync(u => u.Subject == subject);
    }

    public void AddUser(User userToAdd, string password)
    {
        if (userToAdd == null)
        {
            throw new ArgumentNullException(nameof(userToAdd));
        }

        if (string.IsNullOrWhiteSpace(password))
        {
            throw new ArgumentNullException(nameof(password));
        }

        if (_context.Users.Any(u => u.Email == userToAdd.Email))
        {
            throw new Exception("Email must be unique");
        }

        // hash & salt the password
        userToAdd.Password = _passwordHasher.HashPassword(userToAdd, password);
        userToAdd.SecurityCode = Convert.ToBase64String(RandomNumberGenerator.GetBytes(128));
        userToAdd.SecurityCodeExpirationDate = DateTime.UtcNow.AddHours(1);
        _context.Users.Add(userToAdd);
    }

    public async Task<bool> ActivateUserAsync(string securityCode)
    {
        if (string.IsNullOrWhiteSpace(securityCode))
        {
            throw new ArgumentNullException(nameof(securityCode));
        }

        // find an user with this security code as an active security code.  
        var user = await _context.Users.FirstOrDefaultAsync(u =>
            u.SecurityCode == securityCode &&
            u.SecurityCodeExpirationDate >= DateTime.UtcNow);

        if (user == null)
        {
            return false;
        }

        user.Active = true;
        user.SecurityCode = null;
        return true;
    }


    public async Task<bool> SaveChangesAsync()
    {
        return (await _context.SaveChangesAsync() > 0);
    }
}
//----------------------------------Ʌ
```

```C#
//----------------------------V Login Razor Page
[SecurityHeaders]
[AllowAnonymous]
public class Index : PageModel
{
    //private readonly TestUserStore _users;
    private readonly ILocalUserService _localUserService;
    private readonly IIdentityServerInteractionService _interaction;
    private readonly IEventService _events;
    private readonly IAuthenticationSchemeProvider _schemeProvider;
    private readonly IIdentityProviderStore _identityProviderStore;

    public ViewModel View { get; set; } = default!;

    [BindProperty]
    public InputModel Input { get; set; } = default!;

    public Index(
        IIdentityServerInteractionService interaction,
        IAuthenticationSchemeProvider schemeProvider,
        IIdentityProviderStore identityProviderStore,
        IEventService events,
        ILocalUserService localUserService)
    {
        // this is where you would plug in your own custom identity management library (e.g. ASP.NET Identity)
        //_users = users ?? throw new InvalidOperationException("Please call 'AddTestUsers(TestUsers.Users)' on the IIdentityServerBuilder in Startup or remove the TestUserStore from the AccountController.");
        _localUserService = localUserService ?? throw new ArgumentNullException(nameof(localUserService));

        _interaction = interaction;
        _schemeProvider = schemeProvider;
        _identityProviderStore = identityProviderStore;
        _events = events;
    }

    public async Task<IActionResult> OnGet(string? returnUrl)  // ReturnUrl is already "/connect/authorize/callback?client_id=xxxx"
    {
        await BuildModelAsync(returnUrl);
            
        if (View.IsExternalLoginOnly)
        {
            // we only have one option for logging in and it's an external provider
            return RedirectToPage("/ExternalLogin/Challenge", new { scheme = View.ExternalLoginScheme, returnUrl });
        }

        return Page();
    }
        
    public async Task<IActionResult> OnPost()
    {
        // check if we are in the context of an authorization request
        var context = await _interaction.GetAuthorizationContextAsync(Input.ReturnUrl);  // ReturnUrl is "/connect/authorize/callback?client_id=xxxx"

        // the user clicked the "cancel" button
        if (Input.Button != "login")
        {
            if (context != null)
            {
                // This "can't happen", because if the ReturnUrl was null, then the context would be null
                ArgumentNullException.ThrowIfNull(Input.ReturnUrl, nameof(Input.ReturnUrl));

                // if the user cancels, send a result back into IdentityServer as if they 
                // denied the consent (even if this client does not require consent).
                // this will send back an access denied OIDC error response to the client.
                await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                if (context.IsNativeClient())
                {
                    // The client is native, so this change in how to
                    // return the response is for better UX for the end user.
                    return this.LoadingPage(Input.ReturnUrl);
                }

                return Redirect(Input.ReturnUrl ?? "~/");
            }
            else
            {
                // since we don't have a valid context, then we just go back to the home page
                return Redirect("~/");
            }
        }

        if (ModelState.IsValid)
        {
            // validate username/password against in-memory store
            if (await _localUserService.ValidateCredentialsAsync(Input.Username, Input.Password))
            {
                //var user = _users.FindByUsername(Input.Username);
                var user = await _localUserService.GetUserByUserNameAsync(Input.Username);
                await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Subject, user.UserName, clientId: context?.Client.ClientId));
                Telemetry.Metrics.UserLogin(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider);

                // only set explicit expiration here if user chooses "remember me". 
                // otherwise we rely upon expiration configured in cookie middleware.
                var props = new AuthenticationProperties();
                if (LoginOptions.AllowRememberLogin && Input.RememberLogin)
                {
                    props.IsPersistent = true;
                    props.ExpiresUtc = DateTimeOffset.UtcNow.Add(LoginOptions.RememberMeLoginDuration);
                };

                // issue authentication cookie with subject ID and username
                var isuser = new IdentityServerUser(user.Subject)
                {
                    DisplayName = user.UserName
                };

                await HttpContext.SignInAsync(isuser, props);

                if (context != null)
                {
                    // This "can't happen", because if the ReturnUrl was null, then the context would be null
                    ArgumentNullException.ThrowIfNull(Input.ReturnUrl, nameof(Input.ReturnUrl));

                    if (context.IsNativeClient())
                    {
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage(Input.ReturnUrl);
                    }

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    return Redirect(Input.ReturnUrl ?? "~/");
                }

                // request for a local page
                if (Url.IsLocalUrl(Input.ReturnUrl))
                {
                    return Redirect(Input.ReturnUrl);
                }
                else if (string.IsNullOrEmpty(Input.ReturnUrl))
                {
                    return Redirect("~/");
                }
                else
                {
                    // user might have clicked on a malicious link - should be logged
                    throw new ArgumentException("invalid return URL");
                }
            }

            const string error = "invalid credentials";
            await _events.RaiseAsync(new UserLoginFailureEvent(Input.Username, error, clientId:context?.Client.ClientId));
            Telemetry.Metrics.UserLoginFailure(context?.Client.ClientId, IdentityServerConstants.LocalIdentityProvider, error);
            ModelState.AddModelError(string.Empty, LoginOptions.InvalidCredentialsErrorMessage);
        }

        // something went wrong, show form with error
        await BuildModelAsync(Input.ReturnUrl);
        return Page();
    }

    private async Task BuildModelAsync(string? returnUrl)
    {
        Input = new InputModel
        {
            ReturnUrl = returnUrl
        };
            
        var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
        if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
        {
            var local = context.IdP == Duende.IdentityServer.IdentityServerConstants.LocalIdentityProvider;

            // this is meant to short circuit the UI and only trigger the one external IdP
            View = new ViewModel
            {
                EnableLocalLogin = local,
            };

            Input.Username = context.LoginHint;

            if (!local)
            {
                View.ExternalProviders = new[] { new ViewModel.ExternalProvider ( authenticationScheme: context.IdP ) };
            }

            return;
        }

        var schemes = await _schemeProvider.GetAllSchemesAsync();

        var providers = schemes
            .Where(x => x.DisplayName != null)
            .Select(x => new ViewModel.ExternalProvider
            (
                authenticationScheme: x.Name,
                displayName: x.DisplayName ?? x.Name
            )).ToList();

        var dynamicSchemes = (await _identityProviderStore.GetAllSchemeNamesAsync())
            .Where(x => x.Enabled)
            .Select(x => new ViewModel.ExternalProvider
            (
                authenticationScheme: x.Scheme,
                displayName: x.DisplayName ?? x.Scheme
            ));
        providers.AddRange(dynamicSchemes);


        var allowLocal = true;
        var client = context?.Client;
        if (client != null)
        {
            allowLocal = client.EnableLocalLogin;
            if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Count != 0)
            {
                providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
            }
        }

        View = new ViewModel
        {
            AllowRememberLogin = LoginOptions.AllowRememberLogin,
            EnableLocalLogin = allowLocal && LoginOptions.AllowLocalLogin,
            ExternalProviders = providers.ToArray()
        };
    }
}
//----------------------------Ʌ

//---------------------V Registration Razor Page
[SecurityHeaders]
[AllowAnonymous]
public class IndexModel : PageModel
{
    private readonly ILocalUserService _localUserService;
    private readonly IIdentityServerInteractionService _interaction;

    [BindProperty]
    public InputModel Input { get; set; }


    public IndexModel(
        ILocalUserService localUserService,
        IIdentityServerInteractionService interaction)
    {
        _localUserService = localUserService ??
            throw new ArgumentNullException(nameof(localUserService));
        _interaction = interaction ??
            throw new ArgumentNullException(nameof(interaction));
    }

    public IActionResult OnGet(string returnUrl)
    {
        BuildModel(returnUrl);
        return Page();
    }

    public async Task<IActionResult> OnPost()
    {
        if (!ModelState.IsValid)
        {
            // something went wrong, show form with error
            BuildModel(Input.ReturnUrl);
            return Page();
        }

        // create user & claims
        var userToCreate = new Entities.User
        {
            UserName = Input.UserName,
            Subject = Guid.NewGuid().ToString(),
            Email = Input.Email,
            Active = false
        };

        userToCreate.Claims.Add(new Entities.UserClaim()
        {
            Type = "country",
            Value = Input.Country
        });

        userToCreate.Claims.Add(new Entities.UserClaim()
        {
            Type = JwtClaimTypes.GivenName,
            Value = Input.GivenName
        });

        userToCreate.Claims.Add(new Entities.UserClaim()
        {
            Type = JwtClaimTypes.FamilyName,
            Value = Input.FamilyName
        });

        _localUserService.AddUser(userToCreate, Input.Password);
        await _localUserService.SaveChangesAsync();

        // mock emailing user with active code bt creating an activation link and
        // we need an absolute URL, thereforewe use Url.PageLink instead of Url.Page
        var activationLink = Url.PageLink("/user/activation/index",  // <------------https://localhost:5001/User/Activation?securityCode=QwB6XjaepB%2BdOcyxWd4CdMpxxxx
            values: new { securityCode = userToCreate.SecurityCode });

        Console.WriteLine($"Activation link: {activationLink}");
        return Redirect("~/User/ActivationCodeSent");

        //// Issue authentication cookie (log the user in) <--------------------we don't want to log user in anymore after we introduce the activation code
        //var isUser = new IdentityServerUser(userToCreate.Subject)
        //{
        //    DisplayName = userToCreate.UserName
        //};
        //await HttpContext.SignInAsync(isUser);

        //// continue with the flow     
        //if (_interaction.IsValidReturnUrl(Input.ReturnUrl) || Url.IsLocalUrl(Input.ReturnUrl))
        //{
        //    return Redirect(Input.ReturnUrl);
        //}          
    }

    private void BuildModel(string returnUrl)
    {
        Input = new InputModel
        {
            ReturnUrl = returnUrl
        };
    }
}
//---------------------Ʌ
```