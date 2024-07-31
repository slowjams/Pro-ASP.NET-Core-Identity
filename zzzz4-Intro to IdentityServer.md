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

4. `https://localhost:5001/connect/authorize` POST request goes to IdentityServer, `IdentityServerMiddleware`'s `AuthorizeEndpoint` handles it (q2 on IdentityServer4 Source Code)
and `AuthorizeEndpoint` redirects users with `/Account/Login` Razor page content with `ReturnUrl` set to `/connect/authorize/callback...` which flows from the Razor Page's `OnGet` to `OnPost` , the redirection request is below:

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

6. IDP's `IdentityServerMiddleware` handles `/connect/authorize/callback` (HttpContext.User contains "user = Emma" claim), its `AuthorizeCallbackEndpoint` (check c flag) handles this `/connect/authorize/callback` request to generate an auth code (c3.4), then a POST redirection request (to users)`https://localhost:7184/signin-oidc` with auth code (in body, not in querystring as the redirection is POST redirection) is initialize

```C#
/*  https://localhost:7184/signin-oidc POST
    body:
    {
        code: EA4785B99D609C359E14512C70724FFEFFC15F5EA445486B1B072E73CF3FF8CC-1
        scope: openid+profile
        state: CfDJ8Fr2n1UxboNJlI8uHVA4skryuRiPt-1-mhFSMYxXnAqQXXX
        session_state: e35UPvqWXV_cxZ3bBNM-fZEpln9j5Qh4JrVxbX0L9is.28084428FDF3B4FCDC5EDB4D69D3DC4F
        iss: https://localhost:5001
    }
*/
```

7.  `https://localhost:7184/signin-oidc` is handled by `AuthenticationMiddleware` (e1) in ClientApp, then `OpenIdConnectHandler.HandleRequestAsync()` then its base handler `RemoteAuthenticationHandler.HandleRequestAsync()` (OpenIdConnectHandler, o flag, this is where `https://localhost:5001/connect/token` endpoint get called (o3.2) to get access token and id token), also note that we lose "user = Emma" claim in this process because we use IdToken to generate ClaimsIdentity again and this idToken doesn't contain user name for most of time unless we configure it to. Finally, **Client calls `Context.SignInAsync()` to create 'user-to-client' cookie** before redirecting users to its original request e.g home/index

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

A special note on the "user-to-idp cookie" and "user-to-client" cookie. the former is created first on the IdentityServer's end i.e Login page, so the claims will be the data on the signin form (especially the "user = Emma" claim which probably won't be in id token). "user-to-client" cookie however it is created based on id token from idp.

So if you don't clear IDP own session/cookie, and request the resource, resource will be returned to your with no 401 error (bug), behind the scene`AuthorizationMiddleware` calls `OpenIdConnectHandler.HandleChallengeAsync()` to repeat the communication to idp, after  `https://localhost:7184/signin-oidc` is handled by client, Client calls `Context.SignInAsync()` again. If you request the resousrce again,  resource will be returned to you (still a bug), and this time `OpenIdConnectHandler.HandleChallengeAsync()` won't be called


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

```C#
//--------------------------------V IdentityServer runs on https://localhost:5001
public class IdentityServerProgram
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddRazorPages();

        builder.Services
            .AddIdentityServer()
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients)
            .AddTestUsers(TestUsers.Users);

        var app = builder.Build();

        app.UseRouting();

        app.UseIdentityServer();

        app.UseAuthorization();

        app.MapRazorPages().RequireAuthorization();

        app.Run();
    }
}

public static class Config
{
    public static IEnumerable<IdentityResource> IdentityResources =>
        new IdentityResource[]
        { 
            new IdentityResources.OpenId(),  // subject id
            new IdentityResources.Profile(),
            new IdentityResource()
            {
                Name = "verification",
                UserClaims = new List<string>
                {
                    JwtClaimTypes.Email,
                    JwtClaimTypes.EmailVerified
                }
            }
        };

    public static IEnumerable<ApiScope> ApiScopes =>
        new List<ApiScope>
        { 
            new ApiScope("api1", "My API")
        };

    public static IEnumerable<Client> Clients =>
        new List<Client>
        { 
            new Client  // machine to machine client (from quickstart 1)
            {
                ClientId = "client",                                          
                ClientSecrets = {
                    new Secret("secret".Sha256())
                },

                AllowedGrantTypes = GrantTypes.ClientCredentials,

                // scopes that client has access to
                AllowedScopes = { "api1" }
            },
            // interactive ASP.NET Core Web App
            new Client
            {
                ClientId = "web",
                ClientSecrets = { new Secret("secret".Sha256()) },

                AllowedGrantTypes = GrantTypes.Code,

                // where to redirect to after login
                RedirectUris = { "https://localhost:5002/signin-oidc" },
                // where to redirect to after logout
                PostLogoutRedirectUris = { "https://localhost:5002/signout-callback-oidc" },

                AllowedScopes =
                {
                    IdentityServerConstants.StandardScopes.OpenId,
                    IdentityServerConstants.StandardScopes.Profile,
                    "verification"
                }
            }
        };
}
//--------------------------------Ʌ dentityServer
```

```C#
//----------------------V Api
public class ApiProgram   // runs on port 6001
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        builder.Services
            .AddAuthentication("Bearer")
            .AddJwtBearer("Bearer", options =>
            {
                options.Authority = "https://localhost:5001";  // IdentityServer runs on 5001

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = false
                };
            });

        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy("ApiScope", policy =>
            {
                policy.RequireAuthenticatedUser();
                policy.RequireClaim("scope", "api1");
            });
        });

        var app = builder.Build();

        app.UseAuthentication();
        app.UseAuthorization();

        app.MapGet("identity", (ClaimsPrincipal user) => user.Claims.Select(c => new { c.Type, c.Value }))
            .RequireAuthorization("ApiScope");  // ApiScope is the policy name

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