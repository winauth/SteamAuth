SteamAuth for NodeJS
====================

Implementation of mobile SteamGuard 2FA codes and trading confirmations.

## Installation

Expand latest SteamAuth-X.X.X.zip into your project folder.

## Usage

### Authenticator codes

Add require.

	var SteamAuth = require("steamauth"); // if using npm registry
	
	var SteamAuth = require("./SteamAuth"); // if using zip file installation

In normal cases, a time-sync must be done either for SteamAuth or individual SteamAuth instances. This sets the drift between the host computer and Steam servers needed to calculate the correct code.

	// Perform an initial time sync
	SteamAuth.Sync(function(err)
	{
		// we can now create instances
	});
	
Time syncing can also be done on a per-instance basis, by event or callback.

	// create a single instance with ready event
	var auth = new SteamAuth("KNUGC4TFMRJWKY3SMV2A====");
	auth.once("ready", function()
	{
		// auth can now be used
	});

	// create a single instance with callback
	var auth = new SteamAuth("KNUGC4TFMRJWKY3SMV2A====", function(err)
	{
		// auth can now be used
	});

Creating SteamAuth instances can be done with a Base32 string or object with shared_secret.

	// simple example with a Base32 code (from WinAuth)
	var auth = new SteamAuth("KNUGC4TFMRJWKY3SMV2A====");
	var code = auth.calculateCode();

	// example with options loaded from Android Steam mobile app
	var auth = new SteamAuth({
		shared_secret:"U2hhcmVkU2VjcmV0"
	});
	var code = auth.calculateCode();
	
	// calculate a code for a specific time (in ms)
	var code = auth.calculateCode({time:1449690657000);

If you already have the correct time, you can just jump in and create codes.	

	// create an authenticator with no time sync
	var auth = new SteamAuth({
		shared_secret: "U2hhcmVkU2VjcmV0",
		sync: false
	});
	// create code for specific time
	var code = auth.calculateCode({time:1449690657000});

	// quickly create a code for a known secret and time
	var code = SteamAuth.calculateCode("KRUGS42JONGXSQ3PMVLTGRLH", 1449690657000);

	
### Trade Confirmations

Trade confirmations require a login to the SteamAuth instance. In this case, you must additionally pass in the deviceid and identity_secret from the steam authenticator.

	// create instance with options loaded from Android Steam mobile app
	var auth = new SteamAuth({
		deviceid:"android:631471e5-00c8-4e9b-b0e9-45b69426cd09",
		shared_secret:"U2hhcmVkU2VjcmV0",
		identity_secret:"SWRlbnRpdHlTZWNyZXQ="
	});

You can then login with username and password.
	
	// login the user
	auth.login({
		username:"mysteamuser",
		password:"mypassword"
	}, function(err, session)
	{
	});
	
Login can fail because of network errors, but also invalid password, authcode or a captcha is required. If a captcha is required, err will contain captchaid and captchurl properties. The captcha must be solved and passed back in to a new login.

	// login the user with captcha
	auth.login({
		username:"mysteamuser",
		password:"mypassword",
		captchid:12345678,
		captchatext:"ABCDEFG"
	}, function(err, session)
	{
	});
	
On login, you can get an array of the current trade confirmations.

	auth.getTradeConfirmations(function(err, trades)
	{
		if (err || !trades.length) return;	
		
	});

	
Trades are returned as summary objects containing: id:string, key:string, details:string, traded:string, when:string. The id and key are used to accept or reject.
		
	// to accept a trade
	auth.acceptTradeConfirmation(trade.id, trade.key, function(err)
	{
		// trade has been accepted
	});
		
	// to reject a trade
	auth.rejectTradeConfirmation(trade.id, trade.key, function(err)
	{
		// trade has been rejected
	});

## Logging

SteamAuth uses bunyan to log activity. You can get the logger instance at SteamAuth.Logger and set the level, e.g.

	// change logging to be "debug"
	var SteamAuth = require("steamauth");
	SteamAuth.Logger.level("debug");
	
Levels are "error", "warn", "info" and "debug". The default level is "warn".

Debug level logging will include all web request made to the Steam servers.
	
## Tests

	npm test

