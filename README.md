![Logo](https://cdn.hashnode.com/res/hashnode/image/upload/v1723411109872/15d1269c-8fcc-4a72-adba-0222ff595b83.png)

# Purpose of the 'marstore' package
[![Go Reference](https://pkg.go.dev/badge/github.com/jeannot-muller/marstore.svg)](https://pkg.go.dev/github.com/jeannot-muller/marstore)

**marstore** stands for **m**365, **a**uthentication, **r**edis, and (redis)-**store**. This package helps business developers authenticate their users against M365 (business and university) accounts. This package helps with authenticating M365 / Entra services in the Go language.

Developers interested in standard Microsoft online authentication or Azure accounts can try the Goth package: [https://github.com/markbates/goth](https://github.com/markbates/goth)

## Technical documentation

Details can be found here: [https://pkg.go.dev/github.com/jeannot-muller/marstore#pkg-overview](https://pkg.go.dev/github.com/jeannot-muller/marstore#pkg-overview)

### Prerequisites

* A working Redis server for both development and production (required).

* Go-Chi router (recommended).

* A working application in a Microsoft Tenant (required).

* The credentials for that app and properly set URLs for callbacks and logout functionality (required).

* A working internet connection and open firewalls to ensure Microsoft authentication services can be reached.


### Participation

Feel free to fork the repo, suggest changes, or raise issues. Please use the original [GitHub repository](https://github.com/jeannot-muller/marstore) to do so.

## How-Tos

### Use of the library in your own code

Microsoft OAuth authentication workflow follows a logical and simple path:

1. First, the user needs to log in. The example code [here](https://github.com/jeannot-muller/marstore_example) doesn't show a login button, as everyone will follow their own logic. But you can just enter the login path manually into your app.

2. We need a '/login' handler (or any other path you specify) which will forward the request to Microsoft for authentication.

3. Microsoft will call back (with a token) the URL you specified in the properties of the application in your tenant and reflected 1:1 in the configuration structure of your app.

4. The library will store the token and the User structure from Microsoft in a Redis store in the background and write a secure cookie in the browser of the user who made the request.


### Installing a Redis Server Locally or in Production

This page [https://redis.io/docs/latest/get-started/](https://redis.io/docs/latest/get-started/) provides details on how to install the free community edition of Redis on either your development or production system. Overall, this is a straightforward process. Redis Insight is a small desktop app that can help you monitor and check your Redis installation.

### Configuring a Microsoft Application to Get the Necessary Credentials for the Package

The following page [https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app](https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app) outlines the steps to register an application in your Microsoft tenant and obtain the necessary credentials for this package to work.

## Official page
https://jeannot-muller.com/m365-entra-authentication-with-go
