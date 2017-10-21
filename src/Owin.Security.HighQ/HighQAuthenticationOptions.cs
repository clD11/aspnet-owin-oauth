using Authentication.Web.OWIN.HighQ.Provider;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;
using System;
using System.Net.Http;

namespace Authentication.Web.OWIN.HighQ
{
    public class HighQAuthenticationOptions : AuthenticationOptions
    {
        public HighQAuthenticationOptions() : base(Constants.DefaultAuthenticationType)
        {
            Description.Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-highq");
            AuthenticationMode = AuthenticationMode.Passive;
            BackchannelTimeout = TimeSpan.FromSeconds(60);
            CookieManager = new CookieManager();

            AuthorizationEndpoint = Constants.AuthorizationEndpoint;
            TokenEndpoint = Constants.TokenEndpoint;
            UserInformationEndpoint = Constants.UserInformationEndpoint;
        }

        public string ClientId { get; set; }
        public string ClientSecret { get; set; }

        // redirect_uri path in HighQ app registration default is /signin-highq 
        public PathString CallbackPath { get; set; }

        public string SignInAsAuthenticationType { get; internal set; }
        public IHighQAuthenticationProvider Provider { get; set; }
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public string Domain { get; set; } 
        public string InstanceName { get; set; }
        public string RedirectUri { get; set; }

        public string AuthorizationEndpoint { get; private set; }
        public string TokenEndpoint { get; private set; }
        public string UserInformationEndpoint { get; private set; }

        public TimeSpan BackchannelTimeout { get; private set; }
        public ICertificateValidator BackchannelCertificateValidator { get; set; }
        public HttpMessageHandler BackchannelHttpHandler { get; set; }

        public ICookieManager CookieManager { get; set; }

        public string AccessType { get; set; }
        public string ApiVersion { get; set; }
    }
}