using System.Reflection;
using FS.TechDemo.BuyerBFF.Configuration;
using FS.TechDemo.BuyerBFF.Extensions;
using FS.TechDemo.BuyerBFF.GraphQL;
using FS.TechDemo.BuyerBFF.IdentityProvider.Extensions;
using FS.TechDemo.BuyerBFF.Options;
using FS.TechDemo.BuyerBFF.Services;
using FS.TechDemo.Shared;
using MediatR;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.IdentityModel.Logging;
using Serilog;
using Serilog.Events;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddLogging();

// Log.Logger = new LoggerConfiguration()
//     .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
//     .Enrich.FromLogContext()
//     .Enrich.WithMachineName()
//     .Enrich.WithProperty("Assembly", typeof(Program).Assembly.GetName().Name!)
//     .WriteTo.Console()
//     .CreateLogger();

// graphql specific
builder.Services
    .AddGraphQLServer()
    .ModifyRequestOptions(opt => opt.IncludeExceptionDetails = true)
    .AddQueryType<BuyerQuery>()
    .AddMutationType<BuyerMutation>()
    .AddAuthorization();

var configuration = builder.Configuration;

// interface registration
builder.Services.AddScoped<IOrderServiceOut, OrderServiceOut>();
builder.Services.AddScoped<IUserServiceOut, UserServiceOut>();

builder.Services.AddS4HAuthentication(configuration, true);
builder.Services.AddS4hAuthorization();

builder.Services.AddSingleton<ILoggerFactory, LoggerFactory>();

IdentityModelEventSource.ShowPII = true; //Add this line

builder.Services.AddMediatR(Assembly.GetExecutingAssembly());
builder.Services.AddAutoMapper(Assembly.GetExecutingAssembly());
builder.Services.AddOptions().Configure<GrpcOptions>(builder.Configuration.GetSection(GrpcOptions.GrpcOut))
    .Configure<IdentityProviderOptions>(configuration.GetSection(IdentityProviderOptions.IdentityProvider));

builder.Services.AddKeycloak(configuration);

var app = builder.Build();
app.UsePathBase("/buyerbff");
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

app.MapGraphQL();

app.Run();