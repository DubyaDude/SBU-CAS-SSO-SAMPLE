using GSS.Authentication.CAS;
using GSS.Authentication.CAS.AspNetCore;
using GSS.Authentication.CAS.Validation;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace SBU_CAS_SSO_SAMPLE
{
    public static class Auth
    {
        private static bool GlobalAuth = false;
        private static bool ShowAllAuthOptions = false;
        private static string DefaultAuthScheme = "CAS";
        private static IServiceProvider? services = null;
        private static bool DidStonyBrookRemoveCASInTheLogoutURL = true;

        public static void ConfigureService(WebApplicationBuilder builder, bool globalAuth = false, bool didStonyBrookRemoveCASInTheLogoutURL = true)
        {
            GlobalAuth = globalAuth;
            DidStonyBrookRemoveCASInTheLogoutURL = didStonyBrookRemoveCASInTheLogoutURL;
            builder.Services.AddSingleton<IServiceTicketStore, DistributedCacheServiceTicketStore>();
            builder.Services.AddSingleton<ITicketStore, TicketStoreWrapper>();
            //builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            //builder.Services.AddSession();

            if (GlobalAuth)
            {
                builder.Services.AddAuthorization(options =>
                {
                    // Globally Require Authenticated Users
                    options.FallbackPolicy = new AuthorizationPolicyBuilder()
                        .RequireAuthenticatedUser()
                        .Build();
                });
            }
            
            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = new PathString("/auth/login");
                    options.LogoutPath = new PathString("/auth/logout");
                    options.SessionStore = services?.GetRequiredService<ITicketStore>();
                    options.Events = new CookieAuthenticationEvents
                    {
                        OnSigningOut = context =>
                        {
                            string logouturl = builder.Configuration["Authentication:CAS:ServerUrlBase"];
                            if (DidStonyBrookRemoveCASInTheLogoutURL)
                            {
                                int i = logouturl.LastIndexOf("/cas");
                                if (i >= 0)
                                    logouturl = logouturl.Substring(0, i);
                            }

                            // Single Sign-Out
                            var casUrl = new Uri(builder.Configuration["Authentication:CAS:ServerUrlBase"]);
                            var links = context.HttpContext.RequestServices.GetRequiredService<LinkGenerator>();
                            var serviceUrl = new Uri(context.Request.GetEncodedUrl()).GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped);
                            var redirectUri = UriHelper.BuildAbsolute(
                                casUrl.Scheme,
                                new HostString(casUrl.Host, casUrl.Port),
                                casUrl.LocalPath, "/logout",
                                QueryString.Create("service", serviceUrl!));

                            var logoutRedirectContext = new RedirectContext<CookieAuthenticationOptions>(
                                context.HttpContext,
                                context.Scheme,
                                context.Options,
                                context.Properties,
                                redirectUri
                            );
                            context.Response.StatusCode = 204; //Prevent RedirectToReturnUrl
                            context.Options.Events.RedirectToLogout(logoutRedirectContext);
                            return Task.CompletedTask;
                        }
                    };
                })
                .AddCAS(options =>
                {
                    options.CasServerUrlBase = builder.Configuration["Authentication:CAS:ServerUrlBase"];
                    var protocolVersion = builder.Configuration.GetValue("Authentication:CAS:ProtocolVersion", 3);
                    if (protocolVersion != 3)
                    {
                        options.ServiceTicketValidator = protocolVersion switch
                        {
                            1 => new Cas10ServiceTicketValidator(options),
                            2 => new Cas20ServiceTicketValidator(options),
                            _ => null
                        };
                    }

                    options.Events = new CasEvents
                    {
                        OnCreatingTicket = context =>
                        {
                            if (context.Identity == null)
                                return Task.CompletedTask;
                            // Map claims from assertion
                            var assertion = context.Assertion;
                            context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, assertion.PrincipalName));
                            if (assertion.Attributes.TryGetValue("display_name", out var displayName))
                            {
                                context.Identity.AddClaim(new Claim(ClaimTypes.Name, displayName));
                            }

                            if (assertion.Attributes.TryGetValue("email", out var email))
                            {
                                context.Identity.AddClaim(new Claim(ClaimTypes.Email, email));
                            }

                            return Task.CompletedTask;
                        },
                        OnRemoteFailure = context =>
                        {
                            var failure = context.Failure;
                            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<CasEvents>>();
                            if (!string.IsNullOrWhiteSpace(failure?.Message))
                            {
                                logger.LogError(failure, "{Exception}", failure.Message);
                            }

                            context.Response.Redirect("/auth/denied");
                            context.HandleResponse();
                            return Task.CompletedTask;
                        }
                    };
                });
        }


        public static void ConfigureApp(WebApplication app, bool showAllAuthOptions = false, string defaultAuthScheme = "CAS")
        {
            ShowAllAuthOptions = showAllAuthOptions;
            DefaultAuthScheme = defaultAuthScheme;
            services = app.Services;

            //app.UseSession();
            app.UseCasSingleLogout();
            app.UseAuthentication();

            app.Map("/auth/login", branch =>
            {
                branch.Run(async context =>
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

                    var scheme = context.Request.Query["authscheme"];
                    var returnurl = context.Request.Query["ReturnUrl"];
                    if (string.IsNullOrEmpty(returnurl))
                        returnurl = "/";


                    if (ShowAllAuthOptions)
                    {
                        if (!string.IsNullOrEmpty(scheme))
                        {
                            await context.ChallengeAsync(scheme, new AuthenticationProperties { RedirectUri = returnurl });
                            return;
                        }

                        context.Response.ContentType = "text/html";
                        await context.Response.WriteAsync(@"<!DOCTYPE html><html><head><meta charset=""utf-8""></head><body>");
                        await context.Response.WriteAsync("<p>Choose an authentication scheme:</p>");
                        foreach (var type in context.RequestServices.GetRequiredService<IOptions<AuthenticationOptions>>().Value.Schemes)
                        {
                            if (string.IsNullOrEmpty(type.DisplayName)) continue;
                            await context.Response.WriteAsync($"<a href=\"?authscheme={type.Name}&ReturnUrl={returnurl}\">{type.DisplayName ?? type.Name}</a><br>");
                        }
                        await context.Response.WriteAsync("</body></html>");
                    }
                    else
                    {
                        if (string.IsNullOrEmpty(scheme))
                        {
                            scheme = defaultAuthScheme;
                        }

                        await context.ChallengeAsync(DefaultAuthScheme, new AuthenticationProperties { RedirectUri = returnurl });
                    }
                });
            });

            // Sign-out to remove the user cookie.
            app.Map("/auth/logout", branch =>
            {
                branch.Run(async context =>
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    context.Response.Redirect("/");
                });
            });

            app.Map("/auth/denied", branch =>
            {
                branch.Run(async context =>
                {
                    context.Response.ContentType = "text/html";
                    await context.Response.WriteAsync(@"<!DOCTYPE html><html><head><meta charset=""utf-8""></head><body>");
                    await context.Response.WriteAsync("<p>Authentication Failed</p>");
                    await context.Response.WriteAsync("</body></html>");
                });
            });
        }
    }
}
