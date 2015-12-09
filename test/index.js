"use strict";

var url = require("url");
var assert = require("assert");
var nock = require("nock");

var SteamAuth = require("../index.js");

describe("SteamAuth", function()
{
	var interval = 48297900;

	it ("should perform a static time sync", function(done)
	{
		this.timeout(10000);

		SteamAuth.Sync(function(err)
		{
			assert(Math.abs(SteamAuth.Offset) < 60000, "offset seems too large");
			done(err);
		});
	});

	it ("should create a new object", function(done)
	{
		this.timeout(10000);

		// if we want to mock the URL
		//var uri = url.parse(SteamAuth.SYNC_URL);
		//nock(uri.protocol + "//" + uri.host).post(uri.pathname).reply(200, {response:{server_time:Math.floor(new Date().getTime() / 1000)}});

		var auth = new SteamAuth();
		auth.on("error", function(err)
		{
			done(err);
		});
		auth.on("ready", function()
		{
			assert(Math.abs(SteamAuth.Offset) < 60000, "offset seems too large");
			done();
		});
	});

	it ("should create an instance from Base32", function(done)
	{
		var auth = new SteamAuth({secret:"STK7746GVMCHMNH5FBIAQXGPV3I7ZHRG"});
		var code = auth.calculateCode({time:interval * 30000});
		assert.equal(code, "9J4GW", "did not create instance from base32");
		done();
	});

	it ("should create an instance from Base64", function(done)
	{
		var auth = new SteamAuth({secret:"lNX/88arBHY0/ShQCFzPrtH8niY="});
		var code = auth.calculateCode({time:interval * 30000});
		assert.equal(code, "9J4GW", "did not create instance from base32");
		done();
	});

	it ("should create an instance from hex string", function(done)
	{
		var auth = new SteamAuth({secret:"94D5FFF3C6AB047634FD2850085CCFAED1FC9E26"});
		var code = auth.calculateCode({time:interval * 30000});
		assert.equal(code, "9J4GW", "did not create instance from base32");
		done();
	});

	it ("should calculate codes from class method", function(done)
	{
		var code = SteamAuth.calculateCode({secret:"STK7746GVMCHMNH5FBIAQXGPV3I7ZHRG", time:interval * 30000});
		assert.equal(code, "9J4GW", "did not calculate code from class methods");
		done();
	});

	it ("should generate correct codes", function(done)
	{
		var secret = "STK7746GVMCHMNH5FBIAQXGPV3I7ZHRG";

		var auth1 = new SteamAuth({secret:secret, sync:false});
		var auth2 = new SteamAuth({sync:false});

		var testcodes = [
			"9J4GW","9KTV8","TY2MF","WXTYX","JCYC2","V6NXB","FMXY3","VQNKR","JN2VH","JM33B","GHBBP","H5N9M","QF2QQ","F9MDX","4FY8H",
			"DBRQY","M56RD","XP242","TWFRN","VQMKJ","67QFR","MXRPF","63WTY","XDW97","WY9CW","MC5PG","JBTFP","M2PP4","M99RM","VKWN2",
			"W28X3","B8MM8","63R4X","CHFCK","YVK2Y","NFFV5","FFKQJ","YBFM4","YVTB8","596CW","GVFVX","9NHXM","Q46KB","WF5NV","WVT9C",
			"JRVR8","25BDW","P8DG4","XRFM2","N4CMX","QMXN9","22WCF","FND5Y","3Y5WN","B8TYK","BXBRT","M3N6C","V5BN4","VCQW6","3K48H",
			"R934K","N9TVB","CDWM5","DHYWQ","YGNTY","HM766","6YQJF","9RBJ3","8TPRN","6J9HG","CYRFD","58D54","7HQX9","KPKT6","M4HKF",
			"GM9VH","P7892","V6YDM","DHMTH","YWFRT","X3464","GHJMK","DC2GR","9D4G5","DWFY6","8M2NR","RH6MF","X3D6J","C29C9","CB8QH",
			"3YYMW","K3V4Y","75N47","K7PGH","Y68KT","5J5QW","C28TY","WJ89C","NC34M","H3PVQ","7J6P9","BQHQQ","DC3YQ","5BXGX","DNVFW",
			"Y7D65","DX9CW","FB5WJ","JVJPT","R9DR2","W67C7","Y2CVB","K3W93","BC6K3","4JYH8","TP52Q","JK7QX","X9QH6","VNMPX","4F2K7",
			"XH5TC","QP2GG","J5J7K","GYKWJ","JQRT9","HGH6P","964B6","N9FDH","DY938","RW8DQ","V7438","Q5B3P","8VPXQ","FNXPD","2M6R5",
			"9PFVT","YMC4M","Y3NVD","8MH4V","XMRPF","WDV95","V34WW","WKG44","RG9V6","W5355","DJ49N","88TW4","MB9DM","DQV7X","YJM9P",
			"39FT9","D8TF4","NW6TC","HR96Y","P8XPT","53WF6","HMNTK","KQYF8","5F3QX","VNRFX","KX6NW","2HYGB","BTRMH","XQ6TY","BG7FK",
			"VYD7R","7Y6CH","6X77Y","HWK89","5HWTK","8TBPW","45QTM","G49P9","CPM8H","9H8PH","G5Y2G","CCM9J","QVHBB","39B8R","JBYNB",
			"8Y7PX","MVV37","X2X3W","J9MWD","D9Y6Y","2HNTJ","FNRC4","WVXGG","CHFDX","BW655","YF4X3","PQDDJ","QGMQ7","XC45C","NVMKT",
			"WYMWV","6JX4J","GPYF6","M9P22","MFD5D","DRB84","GK33G","JC7XT","JW37W","486R9","TWPDP","WFWPD","K72JF","XKX3Y","QX2BH",
			"QFBHM","3K3JD","PKPB8","YRYM3","PCPYP","4C3H6","YB249","GGDV3","VMB89","8CB8X","8FQXP","NVJMD","2QK6W","V5FDP","7R6BQ",
			"2XJTB","5GCQD","5HP42","J8JG5","R92N6","CTY93","Y6H82","642V5","PTMWV","YY8BH","2KWXD","6RFCT","F9T5Y","C2GR8","W9KN7",
			"D24VR","YM6BV","MTW7J","VPKWT","BMJFY","85B9N","FH75D","TGKFK","4XNG4","WJ6MV","3DPH5","FTNFR","YJN35","22GTD","V9T33",
			"BTGFX","KW6WC","GJKKP","3G8DG","9JGNR","G4N73","3QW3D","5DK7P","2GM5R","7G3RV","DMHCW","6KY8H","K2FR5","577YV","WT26Y",
			"BWKMG","Q9JMN","H9PR3","57YBR","2PGX8","HTRC8","6WK79","JMGJ7","QMJ7W","WX4NM","X74CD","DK2PJ","NQ6CR","DJQ94","Y5VFB",
			"T6335","NYXJY","TPRC3","PGJ49","KMVDK","M3V9R","YYXK3","32CF9","XG8JV","WYBMQ","NHCWD","TVWCX","65B49","XBFWH","K49CK"
		];

		for (var i = 0; i < testcodes.length; i++)
		{
			var code1 = auth1.calculateCode({time: (interval + i) * 30000});
			var code2 = auth2.calculateCode(secret, (interval + i) * 30000);
			if (code1 != testcodes[i] || code2 != testcodes[i])
			{
				done({message:"code mismatch"});
				return;
			}
		}

		done();
	});

	it("should login and get confirmation", function(done)
	{
		if (!process.env["STEAMAUTH_DEVICEID"])
		{
			console.log("Skipping test: requires environment variables: STEAMAUTH_DEVICEID, STEAMAUTH_SHAREDSECRET, STEAMAUTH_IDENTITYSECRET, STEAMAUTH_USERNAME and STEAMAUTH_PASSWORD");
			return done();
		}

		//var uri = url.parse(SteamAuth.COMMUNITY_BASE + "/mobileconf/conf");
		//nock(uri.protocol + "//" + uri.host).post(uri.pathname).reply(200, {response:{server_time:Math.floor(new Date().getTime() / 1000)}});

		var auth = new SteamAuth({
			"deviceid":process.env["STEAMAUTH_DEVICEID"],
			"shared_secret":process.env["STEAMAUTH_SHAREDSECRET"],
			"identity_secret":process.env["STEAMAUTH_IDENTITYSECRET"]
		});
		auth.login({username:process.env["STEAMAUTH_USERNAME"], password:process.env["STEAMAUTH_PASSWORD"] }, function(err, session)
		{
			if (err)
			{
				return done(err);
			}

			auth.getTradeConfirmations(function(err, trades)
			{
				if (err)
				{
					return done(err);
				}

				console.log(trades);

				return done();

				//auth.rejectConfirmation(trades[0].id, trades[0].key, function(err, html)
				//{
				//	done();
				//});
			});
		});
	});
});
