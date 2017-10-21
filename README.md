# ASP.Net Owin OAuth Providers

**1. HighQ**
	
Set as shown in HighQ Developer community.
During app registration set the redirect_uri to *<your_domain>*/signin-highq. 			
For example, https://localhost:44300/signin-highq

In Startup.Auth...
```cs		
app.UseHighQAuthentication(
   new HighQAuthenticationOptions
    {
	ClientId = "<client id>",
	ClientSecret = "<client secret>",
	Domain = "myhq.company.com",
	InstanceName = "myhq",
	ApiVersion = "2",
	// The path once returned from the Identity Provider					
	RedirectUri = "/Account/ExternalLoginCallback",
     }
);
```
