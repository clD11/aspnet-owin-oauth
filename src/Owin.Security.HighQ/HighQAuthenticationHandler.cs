using Microsoft.Owin.Security.Infrastructure;
using System;
using Microsoft.Owin.Security;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using System.Net.Http;
using System.Collections.Generic;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using System.Security.Claims;
using Newtonsoft.Json.Linq;
using Authentication.Web.OWIN.HighQ.Provider;
using System.Net.Http.Headers;
using System.Xml;
using System.Web;

namespace Authentication.Web.OWIN.HighQ
{
    public class HighQAuthenticationHandler : AuthenticationHandler<HighQAuthenticationOptions>
    {
        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public HighQAuthenticationHandler(ILogger logger, HttpClient httpClient)
        {
            this.logger = logger;
            this.httpClient = httpClient;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // Recreate challenge properites as HighQ dosent implement OAuth2 10.12 CSRF i.e. return state on callback...            
            AuthenticationProperties properties = new AuthenticationProperties()
            {
                RedirectUri =
                Request.Scheme +
                Uri.SchemeDelimiter +
                Request.Host +
                Request.PathBase +
                Options.RedirectUri // Use redirect set in AuthenticationOptions.
            };

            try
            {
                string code = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");

                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }
                else
                {
                    return null;
                }

                string state = null;

                values = query.GetValues("state");
                if (values != null && values.Count == 1)
                {
                    state = values[0];
                }

                //properties = Options.StateDataFormat.Unprotect(state);
                //if (properties == null)
                //{
                //    return null;
                //}

                //OAuth2 10.12 CSRF
                //if (!ValidateCorrelationId(properties, logger))
                //{
                //    return new AuthenticationTicket(null, properties);
                //}


                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
                body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
                body.Add(new KeyValuePair<string, string>("client_secret", Options.ClientSecret));
                body.Add(new KeyValuePair<string, string>("code", code));

                // Request the token
                string tokenEndpoint = string.Format(Constants.TokenEndpoint, Options.Domain, Options.InstanceName);
                HttpResponseMessage tokenResponse = await httpClient.PostAsync(tokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                string tokenText = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                JObject response = JObject.Parse(tokenText);
                string accessToken = response.Value<string>("access_token");

                if (string.IsNullOrWhiteSpace(accessToken))
                {
                    logger.WriteWarning("Access token was not found");
                    return new AuthenticationTicket(null, properties);
                }

                // Get the User
                var useremail = response.Value<string>("useremail");
                string userEndpoint = string.Format(Options.UserInformationEndpoint, Options.Domain, Options.InstanceName, Options.ApiVersion, useremail);

                HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, userEndpoint);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
                HttpResponseMessage collaborateResponse = await httpClient.SendAsync(request, Request.CallCancelled);

                collaborateResponse.EnsureSuccessStatusCode();
                string userText = await collaborateResponse.Content.ReadAsStringAsync();

                XmlDocument xmlUser = new XmlDocument();
                xmlUser.LoadXml(userText);

                // Add claims
                var context = HighQAuthenticatedContext.Create(Context, xmlUser, response);

                context.Identity = new ClaimsIdentity(Options.AuthenticationType, ClaimsIdentity.DefaultNameClaimType, ClaimsIdentity.DefaultRoleClaimType);
                context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, ClaimValueTypes.String, Options.AuthenticationType));
                context.Identity.AddClaim(new Claim(ClaimTypes.GivenName, context.FirstName, ClaimValueTypes.String, Options.AuthenticationType));
                context.Identity.AddClaim(new Claim(ClaimTypes.Surname, context.LastName, ClaimValueTypes.String, Options.AuthenticationType));
                context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, ClaimValueTypes.Email, Options.AuthenticationType));

                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode == 401)
            {
                var challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

                if (challenge != null)
                {
                    string requestPrefix = Request.Scheme + "://" + Request.Host;
                    string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                    var authorizationEndpoint = string.Format(Constants.AuthorizationEndpoint, Options.Domain,
                        Options.InstanceName, Options.ClientId, HttpUtility.UrlEncode(redirectUri));

                    var redirectContext = new HighQApplyRedirectContext(Context, Options, challenge.Properties, authorizationEndpoint);
                    Options.Provider.ApplyRedirect(redirectContext);
                }
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null || ticket.Identity == null)
                {
                    logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new HighQReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }

            return false;
        }
    }
}