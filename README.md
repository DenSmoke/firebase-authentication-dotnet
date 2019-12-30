# ViceCode.Firebase.Auth
[![Build Status](https://dev.azure.com/CompLead/TechWiz/_apis/build/status/firebase-authentication-dotnet-CI?branchName=master)](https://dev.azure.com/CompLead/TechWiz/_build/latest?definitionId=13&branchName=master)

Firebase authentication library. It can generate Firebase auth token based on given OAuth token (issued by Google, Facebook...). This Firebase token can then be used with REST queries against Firebase Database endpoints. See [FirebaseDatabase.net](https://github.com/step-up-labs/firebase-database-dotnet) for a C# library wrapping the Firebase Database REST queries.

## Installation
```csharp
// Install release version
Install-Package ViceCode.Firebase.Auth
```

## Supported frameworks
* .NET Core 3.1
* .NET Standard 2.0 - see https://github.com/dotnet/standard/blob/master/docs/versions.md for compatibility matrix

## Supported scenarios
* Login with Google / Facebook / Github / Twitter OAuth tokens
* Anonymous login
* Login with email + password
* Create new user with email + password
* Send a password reset email
* Send a verification email
* Link two accounts together
* Delete account

## Usage

```csharp
var serviceProvider = new ServiceCollection()
    .AddHttpClient()
    .BuildServiceProvider();

var httpClientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>()
var authProvider = new FirebaseAuthProvider(FirebaseApiKey, httpClientFactory);
var facebookAccessToken = "<login with facebook and get oauth access token>";

var auth = await authProvider.SignInWithOAuthAsync(FirebaseAuthType.Facebook, facebookAccessToken);

var options = new FirebaseOptions { AuthTokenAsyncFactory = () => Task.FromResult(auth.FirebaseToken) };
var firebase = new FirebaseClient("https://dinosaur-facts.firebaseio.com/", options);

var dinos = await firebase
    .Child("dinosaurs")
    .OnceAsync<Dinosaur>();
  
foreach (var dino in dinos)
{
    Console.WriteLine($"{dino.Key} is {dino.Object.Height}m high.");
}
```

## Facebook setup

Under [Facebook developers page for your app](https://developers.facebook.com/) make sure you have a similar setup:

![Logo](/art/FacebookSetup.png)


## Google setup

In the [developer console](https://console.developers.google.com/apis/credentials) make sure you have an OAuth client (set it either as iOS or Android app, that should work).
