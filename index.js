/*jslint node: true */
"use strict";

/*
 * Copyright (C) 2015 Colin Mackie <winauth@gmail.com>.
 *
 * This software is distributed under the terms of the GNU General Public License.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// builtin
var util = require('util');
var EventEmitter = require('events').EventEmitter;
var crypto = require("crypto");

// external
var _ = require('underscore');
var base32 = require('rfc-3548-b32');
var request = require("request");
var async = require("async");
var NodeRSA = require('node-rsa');
var cheerio = require("cheerio");

/**
 * Create a new SteamAuth object to create authenticator codes or communicate with Steam
 * passing in either a secret key (base32) string or a config object of auth data.
 *
 * If passing in the secret data from the Steam mobile app (/data/data/com.valvesoftware.android.steam.community/files/SteamGuard-XXXXX),
 *
 * e.g.
 *      var auth = new SteamAuth();
 *      var auth = new SteamAuth("JHYTFVDHSKDHJASGD");
 *      var auth = new SteamAuth({secret:"JHYTFVDHSKDHJASGD"});
 *      var auth = new SteamAuth({
 *        "deviceid":"android:0147986e-a56e-4c59-82df-5b04d813a3a8",
 *        "shared_secret":"4H+kWXz5p5XHk2/5M0C2XQM=",
 *        "identity_secret":"4i14n2+yOn5vq+495mQ+Yirw="
 *        });
 *
 * @param options string secret or mobile app authenticator data
 * @param complete callback(err)
 * @constructor
 */
var SteamAuth = function SteamAuth(options, complete)
{
	var self = this;
	EventEmitter.call(this);

	if (typeof options === "function" && !complete)
	{
		complete = options;
		options = {};
	}
	if (!options)
	{
		options = {};
	}
	if (typeof options === "string")
	{
		options = {secret:options};
	}

	self.session = {};
	self.auth = {};
	if (options.shared_secret)
	{
		_.extend(self.auth, options);
	}
	else if (options.secret)
	{
		_.extend(self.auth, options);
		self.auth.shared_secret = decodeSecretToBuffer(options.secret, options.encoding).toString("base64");
	}

	// synchronise time
	if (!options.time && (typeof options.sync === "undefined" || options.sync))
	{
		// force resync
		if (options.sync === true)
		{
			SteamAuth.Offset = 0;
		}
		SteamAuth.Sync(function(err, offset)
		{
			if (err)
			{
				self.emit("error", err);
				if (complete)
				{
					complete(err);
				}
				return;
			}

			if (complete)
			{
				complete(null, offset);
			}
			self.emit("ready");
		});
	}
	else
	{
		if (complete)
		{
			complete();
		}
		self.emit("ready");
	}
};
util.inherits(SteamAuth, EventEmitter);

/**
 * Interval period i.e. 30 seconds
 * @type {number}
 */
SteamAuth.INTERVAL_PERIOD_MS = 30000;

/**
 * Buffer size of int64
 * @type {number}
 */
SteamAuth.INT64_BUFFER_SIZE = 8;

/**
 * Maximum Int32 value
 * @type {number}
 */
SteamAuth.MAX_INT32 = Math.pow(2,32);

/**
 * Number of digits in SteamGuard code
 * @type {number}
 */
SteamAuth.DIGITS = 5;

/**
 * SteamGuard code character alphabet
 * @type {string[]}
 */
SteamAuth.ALPHABET = [
	'2', '3', '4', '5', '6', '7', '8', '9', 'B', 'C',
	'D', 'F', 'G', 'H', 'J', 'K', 'M', 'N', 'P', 'Q',
	'R', 'T', 'V', 'W', 'X', 'Y'];

/**
 * URL to Steam server sync function
 * @type {string}
 */
SteamAuth.SYNC_URL = "https://api.steampowered.com/ITwoFactorService/QueryTime/v0001";
SteamAuth.COMMUNITY_BASE = "https://steamcommunity.com";
SteamAuth.WEBAPI_BASE = "https://api.steampowered.com";

SteamAuth.Offset = 0;

/**
 * Class method to perform a time sync request to Steam and set offset.
 *
 * @param complete callback with error and offset
 */
SteamAuth.Sync = function(complete)
{
	SteamAuth.Syncing = true;

	if (SteamAuth.Offset)
	{
		setTimeout(function()
		{
			complete(null, SteamAuth.Offset);
		}, 10);
		return;
	}

	request({
				url:SteamAuth.SYNC_URL,
				method:"POST",
				headers:{
					accept: "*/*",
				},
				json:true
			},
			function(err, response, body)
			{
				if (response.statusCode != 200)
				{
					return complete({message:"Non 200 response from Steam"});
				}

				if (!body || !body.response || !body.response.server_time)
				{
					return complete({message:"Invalid time response from Steam"});
				}

				var servertime = parseInt(body.response.server_time) * 1000;
				var offset = SteamAuth.Offset = new Date().getTime() - servertime;

				complete(null, offset);
			}
	);
};

/**
 * Internal function to perform correct request to Steam
 *
 * @param opts url, method, data, cookies and header
 * @param complete callback with err and body
 */
SteamAuth.request = function(opts, complete)
{
	if (!opts.headers)
	{
		opts.headers = {};
	}
	_.extend(opts.headers, {
		accept: "text/javascript, text/html, application/xml, text/xml, */*",
		"User-Agent": "Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; Google Nexus 4 - 4.1.1 - API 16 - 768x1280 Build/JRO03S) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30",
		"Referrer": SteamAuth.COMMUNITY_BASE,
		"X-Requested-With": "com.valvesoftware.android.steam.community"
	});
	if (!opts.cookies)
	{
		opts.cookies = request.jar();
	}

	var reqopts = {
		url:opts.url,
		method:opts.method || "GET",
		headers:opts.headers,
		jar:opts.cookies,
		form:(opts.method == "POST" ? opts.data : null),
		qs:(opts.method == "GET" ? opts.data : null),
		json:!!opts.json
	};

	request(
			reqopts,
			function(err, response, body)
			{
				return complete(err, response, body);
			}
	);
};

/**
 * Login to a new session or update an existing session (e.g. captcha).
 *
 * If not done already, you should add the deviceid value from
 * /data/data/com.valvesoftware.android.steam.community/shared_prefs/steam.uuid.xml
 *
 * var client = new SteamAuth().login({username:"username", password:"password", deviceid:"android-123123"}, complete);
 *
 * If callback returns error, it can be because of invalid password, invalid 2fa code or needing Captcha.
 *
 * @param opts object containing username and password
 * @param complete callback returning (err, session)
 */
SteamAuth.prototype.login = function(opts, complete)
{
	var self = this;

	if (!opts)
	{
		var err = {message: "opts parameter is required"};
		self.emit("error", err);
		if (complete)
		{
			complete(err);
		}
		return;
	}

	var session = self.session || {};

	session.error = null;

	var username = opts.username || session.username;
	var password = opts.password || session.password;

	if (opts.deviceid)
	{
		self.auth.deviceid = opts.deviceid;
	}

	var cookies = session.cookies = (session.cookies || request.jar());
	cookies.setCookie(request.cookie("mobileClientVersion=3067969+%282.1.3%29"), SteamAuth.COMMUNITY_BASE + "/");
	cookies.setCookie(request.cookie("mobileClient=android"), SteamAuth.COMMUNITY_BASE + "/");
	cookies.setCookie(request.cookie("steamid="), SteamAuth.COMMUNITY_BASE + "/");
	cookies.setCookie(request.cookie("steamLogin="), SteamAuth.COMMUNITY_BASE + "/");
	cookies.setCookie(request.cookie("Steam_Language=english"), SteamAuth.COMMUNITY_BASE + "/");
	cookies.setCookie(request.cookie("dob="), SteamAuth.COMMUNITY_BASE + "/");

	async.series([
				// get latest server time
				function(complete)
				{
					SteamAuth.Sync(complete);
				},

				// setup initial cookies
				function(complete)
				{
					if (session.oauth)
					{
						return complete();
					}

					SteamAuth.request({
						url:SteamAuth.COMMUNITY_BASE + "/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client",
						cookies:cookies
					}, function(err, response)
					{
						return complete(err);
					});
				},

				// get RSA key
				function(complete)
				{
					if (session.oauth)
					{
						return complete();
					}

					SteamAuth.request({
						url:SteamAuth.COMMUNITY_BASE + "/login/getrsakey",
						method:"POST",
						data:{username:username},
						cookies:cookies,
						json:true
					}, function(err, response, body)
					{
						if (err)
						{
							return complete(err);
						}
						if (!body.success)
						{
							return complete({message:"Unknown user " + username});
						}

						session.timestamp = body.timestamp;
						session.publicpem = createRsaPublicPem(body.publickey_mod, body.publickey_exp);

						complete();
					});
				},

				// perform login
				function(complete)
				{
					if (session.oauth)
					{
						return complete();
					}

					var key = new NodeRSA(session.publicpem, "public", {encryptionScheme:"pkcs1"});
					var epassword64 = key.encrypt(password, "base64", "utf8");

					var twofactorcode = opts.twofactorcode || "";
					if (!twofactorcode && self.auth && self.auth.shared_secret)
					{
						twofactorcode = self.calculateCode();
					}

					var response = SteamAuth.request({
							url: SteamAuth.COMMUNITY_BASE + "/login/dologin/",
							method: "POST",
							data: {
								username: username,
								password: epassword64,
								twofactorcode: twofactorcode,
								emailauth: opts.emailauthtext || "",
								loginfriendlyname: "#login_emailauth_friendlyname_mobile",
								captchagid: opts.captchaid || "-1",
								captcha_text: opts.captchatext || "enter above characters",
								emailsteamid: (opts.emailauthtext ? session.steamid || "" : ""),
								rsatimestamp: session.timestamp,
								remember_login: "false",
								oauth_client_id: "DE45CD61",
								oauth_scope: "read_profile write_profile read_client write_client",
								donotache: new Date().getTime()
							},
							cookies: cookies,
							json:true
						},
						function(err, response, body)
						{
							if (err)
							{
								return complete(err);
							}
							if (!body)
							{
								return complete({message: "Invalid login response"});
							}

							if (body.emailsteamid)
							{
								session.steamid = body.emailsteamid;
							}

							if (!body.login_complete || !body.oauth)
							{
								if (body.captcha_needed)
								{
									// caller must provide {captchaid, captchatext}
									var captchaid = body.captcha_gid;
									var url = SteamAuth.COMMUNITY_BASE + "/public/captcha.php?gid=" + captchaid;
									err = new Error("Need captcha for " + url);
									err.captchaid = captchaid;
									err.captchaurl = url;
									return complete(err);
								}

								if (body.emailauth_needed)
								{
									// caller must provide {emailauthtext}
									return complete(new Error("Need email auth code " + body.emaildomain || ""));
								}

								if (body.requires_twofactor)
								{
									// caller must provide {twofactorcode}
									return complete(new Error("Need 2FA"));
								}

								return complete(new Error(body.message || "Invalid login"));
							}

							try
							{
								session.oauth = JSON.parse(body.oauth);
							}
							catch (ex)
							{
								complete(ex);
							}
							if (!session.oauth || !session.oauth.oauth_token)
							{
								return complete(new Error("Expected OAUTH token"));
							}

							if (session.oauth.steamid)
							{
								session.steamid = session.oauth.steamid;
							}

							complete();
						}
					);
				}
			],
			function(err)
			{
				if (err)
				{
					return complete(err);
				}

				complete(null, session);
			}
	);
};

/**
 * Get an array of current trade confirmation objects:
 * {
 *   id:confirmation id,
 *   key:confirmation key,
 *   image:<url of trader>,
 *   online:(bool) if trader is online
 *   details:description,
 *   traded:item received,
 *   when:time info
 * }
 *
 * @param complete callback with error or trades array (err, trades)
 */
SteamAuth.prototype.getTradeConfirmations = function(complete)
{
	var self = this;

	if (!self.session || !self.session.oauth)
	{
		return complete({message:"not logged in"});
	}

	var tag = "conf";
	var servertime = Math.floor((new Date().getTime() + (SteamAuth.Offset || 0)) / 1000);
	var timehash = createTimeHash(servertime, tag, self.auth.identity_secret);

	SteamAuth.request({
			url: SteamAuth.COMMUNITY_BASE + "/mobileconf/conf",
			method: "GET",
			data: {
				p: self.auth.deviceid,
				a: self.session.steamid,
				k: timehash,
				t: servertime,
				m: "android",
				tag: tag
			},
			cookies: self.session.cookies,
			json:true
		},
		function(err, response, body)
		{
			if (err)
			{
				return complete(err);
			}

			var trades = [];

			var $ = cheerio.load(body);
			$(".mobileconf_list_entry").each(function()
			{
				var $entry = $(this);

				var id = $entry.attr("data-confid");
				if (id)
				{
					var trade = {id:id};
					trade.key = $entry.attr("data-key");

					trade.image = $(".mobileconf_list_entry_icon img", $entry).attr("src");

					var $details = $(".mobileconf_list_entry_description > div", $entry);
					trade.details = $details.length > 0 ? $details.eq(0).html() : "";
					trade.traded = $details.length > 1 ? $details.eq(1).html() : "";
					trade.when = $details.length > 2 ? $details.eq(2).html() : "";

					trades.push(trade);
				}
			});

			complete(null, trades);
		}
	);
};

/**
 * Reject a trade confirmation by its id and key from getTradeConfirmations
 *
 * @param id id of trade
 * @param key key for trade
 * @param complete (err) return err if error or failed
 */
SteamAuth.prototype.rejectTradeConfirmation = function(id, key, complete)
{
	this.sendConfirmation(id, key, "cancel", complete);
};

/**
 * Accept a trade confirmation by its id and key from getTradeConfirmations
 *
 * @param id id of trade
 * @param key key for trade
 * @param complete (err) return err if error or failed
 */
SteamAuth.prototype.acceptTradeConfirmation = function(id, key, complete)
{
	this.sendConfirmation(id, key, "allow", complete);
};

/**
 * Send a trade confirmation response
 *
 * @param id id of trade
 * @param key key for trade
 * @param tag tag of response, e.g "cancel", "allow"
 * @param complete (err) if error or failed
 * @returns {*}
 */
SteamAuth.prototype.sendConfirmation = function(id, key, tag, complete)
{
	var self = this;

	if (!self.session || !self.session.oauth)
	{
		return complete({message:"not logged in"});
	}

	var servertime = Math.floor((new Date().getTime() + (SteamAuth.Offset || 0)) / 1000);
	var timehash = createTimeHash(servertime, tag, self.auth.identity_secret);

	SteamAuth.request({
				url: SteamAuth.COMMUNITY_BASE + "/mobileconf/ajaxop",
				method: "GET",
				data: {
					op: tag,
					p: self.auth.deviceid,
					a: self.session.steamid,
					k: timehash,
					t: servertime,
					m: "android",
					tag: tag,
					cid: id,
					ck: key
				},
				cookies: self.session.cookies,
				json:true
			},
			function(err, response, body)
			{
				if (err)
				{
					return complete(err);
				}
				if (!body.success)
				{
					return complete(new Error("Unable to " + tag + " " + id));
				}

				complete();
			}
	);
};

/**
 * Get full details about a trade confirmation
 *
 * NOT YET IMPLEMENTED
 *
 * @param id of of trade
 * @param complete (err,trade) err if error occured, else trade object
 * @returns {*}
 */
SteamAuth.prototype.getTradeConfirmation = function(id, complete)
{
	var self = this;

	if (!self.session || !self.session.oauth)
	{
		return complete({message:"not logged in"});
	}

	var tag = "details" + id;
	var servertime = Math.floor((new Date().getTime() + (SteamAuth.Offset || 0)) / 1000);
	var timehash = createTimeHash(servertime, tag, self.auth.identity_secret);

	SteamAuth.request({
				url: SteamAuth.COMMUNITY_BASE + "/mobileconf/details/" + id,
				method: "GET",
				data: {
					p: self.auth.deviceid,
					a: self.session.steamid,
					k: timehash,
					t: servertime,
					m: "android",
					tag: tag
				},
				cookies: self.session.cookies,
				json:true
			},
			function(err, response, body)
			{
				if (err)
				{
					return complete(err);
				}
				if (!body.success)
				{
					return complete(new Error("Unknown Conf " + id));
				}

				var $ = cheerio.load(body.html);
				var $trade = $(".mobileconf_trade_area");
				if (!$trade.length)
				{
					return complete(new Error("Cannot find trade"));
				}

				var trade = {partner:{}, items:[], receiving:[]};
				var $partner = $(".trade_partner_header", $trade);
				trade.partner.name = $(".trade_partner_headline_sub a", $partner).html();
				trade.partner.steamid = /[\s\S]*\/profiles\/([\s\S]*)/i.exec($(".trade_partner_headline_sub a", $partner).attr("href"));
				//trade.partner.icon = $(".trade_partner_icon img", $partner).attr("src");

				//$(".tradeoffer_item.primary")

				complete(null, trade, body.html);
			}
	);
};

/**
 * Convienience class method for quick call to calculate authenticator code
 *
 * @param options secret key or options object (see SteamAuth::calculateCode)
 * @param time optional time in ms
 * @returns {string} authenticator code
 */
SteamAuth.calculateCode = function(options, time)
{
	if (typeof options === "string")
	{
		options = {secret:options};
	}
	if (time)
	{
		options.time = time;
	}
	var auth = new SteamAuth({sync:!options.time});
	return auth.calculateCode(options);
};

/**
 * Calculate the SteamGuard code from the current or supplied time given Base32 secret key.
 * If the time is supplied, it must include any drift between the host and Steam servers.
 *
 * @param options Either Base32 (RFC3548) encoded secret key or options object {secret:encoded secret key,
 *                time:time to use in ms, encoding:base32|base64|hex encoding of secret}
 * @returns {string} 5 character SteamGuard code
 */
SteamAuth.prototype.calculateCode = function(options, time)
{
	var self = this;

	if (!options)
	{
		options = {};
	}
	else if (typeof options === "string")
	{
		options = {shared_secret:decodeSecretToBuffer(options, "base32")};
	}
	if (time)
	{
		options.time = time;
	}

	var secretBuffer;
	if (options.secret)
	{
		secretBuffer = decodeSecretToBuffer(options.secret, options.encoding || "base32");
	}
	else if (options.shared_secret)
	{
		secretBuffer = decodeSecretToBuffer(options.shared_secret, options.encoding || "base64");
	}
	else if (self.auth)
	{
		secretBuffer = decodeSecretToBuffer(self.auth.shared_secret, "base64");
	}
	else
	{
		var err = {message:"No secret key defined"};
		self.emit("error", err);
		throw err;
	}

	// use the current or supplier time
	time = options.time;
	if (!time)
	{
		time = new Date().getTime() + SteamAuth.Offset;
	}

	// calculate interval
	var interval = Math.floor(time / SteamAuth.INTERVAL_PERIOD_MS);
	var buffer = new Buffer(SteamAuth.INT64_BUFFER_SIZE);
	buffer.writeUInt32BE(Math.floor(interval / SteamAuth.MAX_INT32), 0);
	buffer.writeUInt32BE(interval % SteamAuth.MAX_INT32, 4);

	// create hash
	var hmac = crypto.createHmac("sha1", secretBuffer);
	var mac = hmac.update(buffer).digest();

	// extract code value from hash
	var start = mac[19] & 0x0f;
	var value = mac.readUInt32BE(start) & 0x7fffffff;

	// convert code value into char values
	var code = "";
	for (var i=0; i<SteamAuth.DIGITS; i++)
	{
		code += SteamAuth.ALPHABET[value % SteamAuth.ALPHABET.length];
		value = Math.floor(value / SteamAuth.ALPHABET.length);
	}

	return code;
};

/**
 * Decode a secret string from the given or guessed encoding into a Buffer
 *
 * @param secret encoded secret string
 * @returns {*} Buffer containing secret
 */
function decodeSecretToBuffer(secret, encoding)
{
	if (!secret || secret instanceof Buffer)
	{
		return secret;
	}

	if (!encoding)
	{
		if (/^([ABCDEF0-9]{2})+$/i.test(secret))
		{
			// test for hex
			encoding = "hex";
		}
		else if (/^[ABCDEFGHIJKLMNOPQRSTUVWXYZ234567]+$/.test(secret))
		{
			// test for base32
			encoding = "base32";
		}
		else
		{
			// else probably base64
			encoding = "base64";
		}
	}
	// test for hex
	if (encoding == "hex")
	{
		return new Buffer(secret, "hex");
	}
	else if (encoding == "base32")
	{
		return base32.decode(secret);
	}
	else if (encoding == "base64")
	{
		return new Buffer(secret, "base64");
	}
	else
	{
		throw {message:"Unknown encoding " + encoding};
	}
}

/**
 * Convert a public key modulus and exponent into a pkcs8 pem
 *
 * @param modulus
 * @param exponent
 * @returns {string}
 */
function createRsaPublicPem(modulus, exponent)
{
	function prepadSigned(hexStr)
	{
		var msb = hexStr[0];
		if ((msb>='8' && msb<='9') || (msb>='a' && msb<='f') || (msb>='A'&&msb<='F'))
		{
			return "00" + hexStr;
		}
		else
		{
			return hexStr;
		}
	}

	function toHex(number)
	{
		var nstr = number.toString(16);
		if (nstr.length % 2 === 0)
		{
			return nstr;
		}
		else
		{
			return "0" + nstr;
		}
	}

	// encode ASN.1 DER length field
	// if <=127, short form
	// if >=128, long form
	function encodeLengthHex(n)
	{
		if (n <= 127)
		{
			return toHex(n);
		}
		else
		{
			var n_hex = toHex(n);
			var length_of_length_byte = 128 + n_hex.length/2; // 0x80+numbytes
			return toHex(length_of_length_byte)+n_hex;
		}
	}

	modulus = prepadSigned(modulus);
	exponent = prepadSigned(exponent);

	var modlen = modulus.length/2;
	var explen = exponent.length/2;

	var encoded_modlen = encodeLengthHex(modlen);
	var encoded_explen = encodeLengthHex(explen);
	var encoded_pubkey = "30" +
			encodeLengthHex(
					modlen +
					explen +
					encoded_modlen.length/2 +
					encoded_explen.length/2 + 2
			) +
			"02" + encoded_modlen + modulus +
			"02" + encoded_explen + exponent;

	var seq2 = "30 0d " +
			"06 09 2a 86 48 86 f7 0d 01 01 01" +
			"05 00 " +
			"03" + encodeLengthHex(encoded_pubkey.length/2 + 1) +
			"00" + encoded_pubkey;

	seq2 = seq2.replace(/ /g, "");

	var der_hex = "30" + encodeLengthHex(seq2.length/2) + seq2;

	der_hex = der_hex.replace(/ /g, "");

	var der = new Buffer(der_hex, "hex");
	var der_b64 = der.toString("base64");

	return "-----BEGIN PUBLIC KEY-----\n" + der_b64.match(/.{1,64}/g).join("\n") + "\n-----END PUBLIC KEY-----\n";
}

/**
 * Create the time hash for Steam mobile calls
 *
 * @param time current time
 * @param tag operation tag
 * @param secret identity_secret
 * @returns base64 hash
 */
function createTimeHash(time, tag, secret)
{
	var b64secret = new Buffer(secret, "base64");

	var bufferSize = 8;
	if (tag)
	{
		bufferSize += Math.min(32, tag.length);
	}
	var buffer = new Buffer(bufferSize);

	buffer.writeUInt32BE(Math.floor(time / SteamAuth.MAX_INT32), 0);
	buffer.writeUInt32BE(time % SteamAuth.MAX_INT32, 4);

	if (tag)
	{
		buffer.write(tag, 8, bufferSize - 8, "utf8");
	}

	var hmac = crypto.createHmac("sha1", b64secret);
	var mac = hmac.update(buffer).digest();

	return mac.toString("base64");
}

module.exports = SteamAuth;
