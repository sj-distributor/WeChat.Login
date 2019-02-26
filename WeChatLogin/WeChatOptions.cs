using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace WeChatLogin
{
    public class WeChatOptions : OAuthOptions
    {
        private readonly string loginScope = "snsapi_login";
        private readonly string userInfoScope = "snsapi_userinfo";

        /// <summary>
        /// Initializes a new <see cref="WeChatOptions"/>.
        /// </summary>
        public WeChatOptions()
        {
            CallbackPath = new PathString("/signin-wechat");
            TokenEndpoint = WeChatDefaults.TokenEndpoint;
            UserInformationEndpoint = WeChatDefaults.UserInformationEndpoint;

            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "openid");
            ClaimActions.MapJsonKey(ClaimTypes.Name, "nickname");
            ClaimActions.MapJsonKey(ClaimTypes.Gender, "sex", ClaimValueTypes.Integer);
            ClaimActions.MapJsonKey(ClaimTypes.Country, "country");
            ClaimActions.MapJsonKey(ClaimTypes.Uri, "headimgurl");
            ClaimActions.MapJsonKey("urn:wechat:province", "province");
            ClaimActions.MapJsonKey("urn:wechat:city", "city");
            ClaimActions.MapJsonKey("urn:wechat:unionid", "unionid");
            ClaimActions.MapCustomJson("urn:wechat:privilege", user => string.Join(",", user.SelectToken("privilege")?.Select(s => (string)s).ToArray() ?? new string[0]));
        }

        /// <summary>
        /// Gets or sets the WeChat-assigned appId.
        /// </summary>
        public string AppId
        {
            get
            {
                return ClientId;
            }
            set
            {
                ClientId = value;
            }
        }

        /// <summary>
        /// Gets or sets the WeChat-assigned app secret.
        /// </summary>
        public string AppSecret
        {
            get
            {
                return ClientSecret;
            }
            set
            {
                ClientSecret = value;
            }
        }

        public AppType AppType
        {
            set
            {
                Scope.Add(userInfoScope);

                switch (value)
                {
                    case AppType.Mobile:
                        AuthorizationEndpoint = WeChatDefaults.MobileAuthorizationEndpoint;
                        break;
                    case AppType.Web:
                        Scope.Add(loginScope);
                        AuthorizationEndpoint = WeChatDefaults.WebAuthorizationEndpoint;
                        break;
                }
            }
        }
    }

    public enum AppType
    {
        Mobile,
        Web
    }
}