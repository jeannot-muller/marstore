# marstore

**marstore** stands for m365, authentication, redis, and (redis)-store. The purpose of this package is to help people
involved into business development to authenticate their users against M365 (business and university) accounts.

Developers interested in standard microsoft online authentication and / or azure accounts can try the Goth package: https://github.com/markbates/goth

## Technical documentation
Details can be found here: https://pkg.go.dev/github.com/jeannot-muller/marstore#pkg-overview

### Prerequisites
+ A working redis server in development and production (must have).
+ Go-Chi router (recommended).
+ A working application in a Microsoft Tenant (must have).
+ The credentials for that app and properly set URLs for callbacks and logout functionality (must have).
+ A working internet connection and open firewalls as such that the Microsoft authentication services can be reached.

### Participation
Feel free to fork the repo, suggest changes or raise issues. Please use the original github.com repository to do so: .https://github.com/jeannot-muller/marstore

## How-Tos
### Use of the library in your own code
The authentication follows a logical and simple path:

1. First the user needs to log in. The example code https://github.com/jeannot-muller/marstore_example doesn't show 
   a login button or the like, as anyone will follow their own logic. But you can just enter the login path manually 
   into your app.
2. We need a '/login' handler (or any other path you specify) which will forward the request to Microsoft for 
   authentication.
3. Microsoft will call back (with a token) the url you specified in the properties of the application in your tenant 
   and reflected 1:1 in the configuration structure of your app.
4. The library will store in the background the token and the User structure from Microsoft in a redis store and 
   write a secure cookie in the browser of the user who made the request.

### Installing a Redis Server locally / in production
This page https://redis.io/docs/latest/get-started/ shows you the details to install the free community edition of Redis on either your development or your productive system, overall this is a quite straightforward process.
Redis Insight is a small Desktop App which might help you to monitor and check your Redis installation.

### Configuring a Microsoft Application to get the necessary credentials for the package config
The following page https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app shows you the necessary steps to register an application in your Microsoft tenant and to get the necessary credentials for this package to work. 
