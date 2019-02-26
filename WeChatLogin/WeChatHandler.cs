using Newtonsoft.Json.Linq;
using System;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Text.Encodings.Web;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.AspNetCore.WebUtilities;

namespace WeChatLogin
{
    public class WeChatHandler : OAuthHandler<WeChatOptions>
    {
        public WeChatHandler(IOptionsMonitor<WeChatOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            AuthenticationProperties properties = null;

            var query = Request.Query;
            var error = query["error"];

            if (!string.IsNullOrEmpty(error))
            {
                var errorUri = query["error_uri"];
                var errorDescription = query["error_description"];

                var errorMsg = $"[ErrorUri: {errorUri}] [ErrorDescription: {errorDescription}]";

                return HandleRequestResult.Fail(errorMsg);
            }

            var code = query["code"];
            var state = query["state"];

            properties = Options.StateDataFormat.Unprotect(state);

            if (properties == null)
            {
                return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            }

            if (StringValues.IsNullOrEmpty(code))
            {
                return HandleRequestResult.Fail("Code was not found.");
            }

            var tokens = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));

            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error);
            }

            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.");
            }

            var identity = new ClaimsIdentity(Options.ClaimsIssuer);

            AuthenticationTicket ticket = await CreateTicketAsync(identity, properties, tokens);

            if (ticket != null)
            {
                return HandleRequestResult.Success(ticket);
            }
            else
            {
                return HandleRequestResult.Fail("Failed to retrieve user information from remote server.");
            }
        }

        /// <summary>
        /// 第一步，构建获取AuthorizationCode请求。
        /// </summary>
        /// <param name="properties"></param>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            var scope = FormatScope();

            var state = Options.StateDataFormat.Protect(properties);

            var parameters = new Dictionary<string, string>()
            {
                { "appid", Options.ClientId },
                { "redirect_uri", redirectUri },
                { "response_type", "code" },
            };

            var endpoint = QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, parameters);

            //scope不能Encode。
            endpoint += $"&scope={scope}&state={state}";

            return endpoint;
        }

        /// <summary>
        /// 第二步，通过AuthorizationCode获取AccessToken。
        /// </summary>
        /// <param name="code"></param>
        /// <param name="redirectUri"></param>
        /// <returns></returns>
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            var parameters = new Dictionary<string, string>()
            {
                { "code", code },
                { "appid", Options.ClientId },
                { "secret", Options.ClientSecret },
                { "grant_type", "authorization_code" },
            };

            var endpoint = QueryHelpers.AddQueryString(Options.TokenEndpoint, parameters);

            var response = await Backchannel.GetAsync(endpoint, Context.RequestAborted);

            if (response.IsSuccessStatusCode)
            {
                var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

                return OAuthTokenResponse.Success(payload);
            }
            else
            {
                return OAuthTokenResponse.Failed(new Exception("OAuth token endpoint failure."));
            }
        }

        /// <summary>
        /// 第三步，创建身份票据
        /// </summary>
        /// <param name="identity"></param>
        /// <param name="properties"></param>
        /// <param name="tokens"></param>
        /// <returns></returns>
        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var openId = GetOpenId(tokens.Response);

            var parameters = new Dictionary<string, string>
            {
                { "access_token", tokens.AccessToken },
                { "openid",  openId },
                { "lang", "zh_CN" }
            };

            var userInfoEndpoint = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, parameters);

            var response = await Backchannel.GetAsync(userInfoEndpoint, Context.RequestAborted);

            if (!response.IsSuccessStatusCode)
            {
                throw new HttpRequestException($"Failed to retrieve WeChat user information ({response.StatusCode}) Please check if the authentication information is correct and the corresponding WeChat Graph API is enabled.");
            }

            var userInfo = JObject.Parse(await response.Content.ReadAsStringAsync());

            var oAuthCreatingTicketContext = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, userInfo);

            oAuthCreatingTicketContext.RunClaimActions();

            await Options.Events.CreatingTicket(oAuthCreatingTicketContext);

            return new AuthenticationTicket(oAuthCreatingTicketContext.Principal, oAuthCreatingTicketContext.Properties, Scheme.Name);
        }

        protected override string FormatScope()
        {
            return string.Join(",", Options.Scope);
        }

        private string GetOpenId(JObject json)
        {
            return json.Value<string>("openid");
        }
    }
}