using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Logging;
using System.Net.Http;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.DataHandler;
using Authentication.Web.OWIN.HighQ.Provider;
using System;
using System.Globalization;

namespace Authentication.Web.OWIN.HighQ
{
    public class HighQAuthenticationMiddleware : AuthenticationMiddleware<HighQAuthenticationOptions>
    {
        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public HighQAuthenticationMiddleware(OwinMiddleware next, IAppBuilder app, HighQAuthenticationOptions options) : base(next, options)
        {
            logger = app.CreateLogger<HighQAuthenticationMiddleware>();

            validateAuthenticationOptions(options);

            if (Options.Provider == null)
            {
                Options.Provider = new HighQAuthenticationProvider();
            }

            // TODO - possibly dont need this as HighQ dosent return state NEEDS TESTING
            if (options.StateDataFormat == null)
            {
                IDataProtector dataProtector = app.CreateDataProtector(typeof(HighQAuthenticationMiddleware).FullName,
                    options.AuthenticationType, "v1");
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (string.IsNullOrEmpty(Options.SignInAsAuthenticationType))
            {
                options.SignInAsAuthenticationType = app.GetDefaultSignInAsAuthenticationType();
            }

            httpClient = new HttpClient(ResolveHttpMessageHandler(Options));
            httpClient.Timeout = Options.BackchannelTimeout;
            httpClient.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
        }

        protected override AuthenticationHandler<HighQAuthenticationOptions> CreateHandler()
        {
            return new HighQAuthenticationHandler(logger, httpClient);
        }

        private static HttpMessageHandler ResolveHttpMessageHandler(HighQAuthenticationOptions options)
        {
            HttpMessageHandler handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                var webRequestHandler = handler as WebRequestHandler;

                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("Exception: ValidatorHandlerMismatch");
                }

                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            return handler;
        }

        private void validateAuthenticationOptions(HighQAuthenticationOptions options)
        {
            string message = "Exception: Option {0} must be provided";

            if (string.IsNullOrWhiteSpace(Options.ClientId))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "ClientId"));
            }

            if (string.IsNullOrWhiteSpace(Options.ClientSecret))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "ClientSecret"));
            }

            if (string.IsNullOrEmpty(options.Domain))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "Domain"));
            }

            if (string.IsNullOrEmpty(options.InstanceName))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "InstanceName"));
            }

            if (string.IsNullOrEmpty(options.ApiVersion))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "ApiVersion"));
            }

            if (string.IsNullOrEmpty(options.RedirectUri))
            {
                throw new ArgumentException(string.Format(CultureInfo.CurrentCulture, message, "RedirectUri"));
            }
        }
    }
}