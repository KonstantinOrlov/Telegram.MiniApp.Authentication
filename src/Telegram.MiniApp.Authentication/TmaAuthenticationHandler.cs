using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Neftm.TelegramMiniApp.Authorization.Constants;
using Neftm.TelegramMiniApp.Authorization.Helpers;
using Neftm.TelegramMiniApp.Authorization.Models;
using System.Collections.Specialized;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Web;

namespace Neftm.TelegramMiniApp.Authorization;

/// <summary>
/// Handles authentication for Telegram Mini App
/// </summary>
public class TmaAuthenticationHandler : AuthenticationHandler<TmaAuthenticationOptions>
{
#if NET8_0
    public TmaAuthenticationHandler(
        IOptionsMonitor<TmaAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder) :
        base(options, logger, encoder)
    { }
#elif NET6_0_OR_GREATER
	public TmaAuthenticationHandler(
		IOptionsMonitor<TmaAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder,
		ISystemClock clock) :
		base(options, logger, encoder, clock) { }
#endif

    /// <summary>
    /// Handles authentication
    /// </summary>
    /// <returns>Authentication result.</returns>
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var token = Request.Headers[Options.TokenHeaderName].ToString();

        if (!string.IsNullOrWhiteSpace(token))
        {
            var tokenPrefix = token.Split(" ").FirstOrDefault();

            if (!string.IsNullOrWhiteSpace(tokenPrefix))
            {
                if (tokenPrefix.ToLowerInvariant() == TmaDefaults.AuthenticationScheme.ToLowerInvariant())
                {
                    token = token.Split(" ").Skip(1).FirstOrDefault();

                    if (token is not null)
                    {
                        var data = HttpUtility.ParseQueryString(token);

                        if (InitDataIsValid(data))
                        {
                            // Set feature & claims
                            Request.HttpContext.Features.Set(data);
                            var claims = BuildClaims(data);

                            var claimsIdentity = new ClaimsIdentity(claims, Scheme.Name);
                            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

                            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal, Scheme.Name)));
                        }

                        return Task.FromResult(AuthenticateResult.Fail($"Invalid token"));
                    }
                }
            }

            return Task.FromResult(AuthenticateResult.NoResult());
        }

        return Task.FromResult(AuthenticateResult.Fail($"Missing Authorization header"));
    }

    private bool InitDataIsValid(NameValueCollection? data)
    {
        if (data is not null)
            if (!string.IsNullOrWhiteSpace(data[TmaInitDataKeys.Hash]))
                if (!string.IsNullOrWhiteSpace(data[TmaInitDataKeys.AuthDate]))
                    if (HashHelper.CalculateTmaHash(BuildDataCheckString(data), Options.BotToken) == data[TmaInitDataKeys.Hash])
                        return true;

        return false;
    }

    private string BuildDataCheckString(NameValueCollection input)
    {
        return string.Join("\n",
            input.AllKeys
                .Where(d => d != TmaInitDataKeys.Hash)
                .OrderBy(x => x)
                .Select(x => $"{x}={input[x]}"));
    }

    private List<Claim> BuildClaims(NameValueCollection data)
    {
        var claims = new List<Claim>();

        var userJson = data[TmaInitDataKeys.User];

        if (!string.IsNullOrWhiteSpace(userJson))
        {
            var user = JsonSerializer.Deserialize<TmaInitDataUser>(userJson);

            if (user is not null)
            {
                claims.AddRange(new List<Claim>()
                {
                    new(TmaClaimTypes.UserId, user.Id.ToString()),
                    new(TmaClaimTypes.FirstName, user.FirstName),
                    new(TmaClaimTypes.IsPremium, user.IsPremium.ToString()),
                });

                //Possible empty
                if (!string.IsNullOrWhiteSpace(user.UserName))
                    claims.Add(new Claim(TmaClaimTypes.UserName, user.UserName));

                if (!string.IsNullOrWhiteSpace(user.LastName))
                    claims.Add(new Claim(TmaClaimTypes.LastName, user.LastName));
            }
        }

        var chatInstanceString = data[TmaInitDataKeys.ChatInstance];

        if (!string.IsNullOrWhiteSpace(chatInstanceString))
        {
            claims.Add(new Claim(TmaClaimTypes.ChatInstance, chatInstanceString));
        }

        return claims;
    }
}