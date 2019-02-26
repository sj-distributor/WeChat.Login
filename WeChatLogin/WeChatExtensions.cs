using System;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;

namespace WeChatLogin
{
    public static class WeChatExtensions
    {
        public static AuthenticationBuilder AddWeChat(this AuthenticationBuilder builder)
        {
            return builder.AddWeChat("WeChat", (WeChatOptions _) => {});
        }

        public static AuthenticationBuilder AddWeChat(this AuthenticationBuilder builder, Action<WeChatOptions> configureOptions)
        {
            return builder.AddWeChat("WeChat", configureOptions);
        }

        public static AuthenticationBuilder AddWeChat(this AuthenticationBuilder builder, string authenticationScheme, Action<WeChatOptions> configureOptions)
        {
            return builder.AddWeChat(authenticationScheme, WeChatDefaults.DisplayName, configureOptions);
        }

        public static AuthenticationBuilder AddWeChat(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<WeChatOptions> configureOptions)
        {
            return builder.AddOAuth<WeChatOptions, WeChatHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}