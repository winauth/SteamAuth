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
var http = require("http");
var https = require("https");
var Url = require("url");

// external
var base32 = require('rfc-3548-b32');

/**
 * A SteamAuth instance used to generates SteamGuard authenticator codes
 *
 * SteamAuth should be synced with Steam to ensure correct drift between the host and server times,
 * used to generate the correct codes. SteamAuth will get the latest server time from Steam by default,
 * but can be disabled by passing options {sync:false}.
 *
 * usage:
 *
 *   var auth = new SteamAuth(); // time sync will happen for first instance
 *   auth.on("ready", function()
 *   {
 *     auth.calculateCode("ABCDEGHJ");
 *   });
 *
 *   // or calculate code directly from SteamAuth - but the time must match Steam server
 *   var code = SteamAuth.calculateCode("ABCDEGHJ", new Date().getTime());
 *
 * @param options optional options object: sync: true(default)/false, to perform a time sync request from Steam servers
 * @param complete optional callback when ready (or "ready" event fired)
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

	if (options.secret)
	{
		self._secret = decodeSecretToBuffer(options.secret, options.encoding);
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

SteamAuth.Offset = 0;

/**
 * Class method to perform a time sync request to Steam and set offset.
 *
 * @param complete callback with error and offset
 */
SteamAuth.Sync = function(complete)
{
	if (SteamAuth.Offset)
	{
		return complete(null, SteamAuth.Offset);
	}

	var url = Url.parse(SteamAuth.SYNC_URL);
	var protocol = (url.protocol === "https:" ? https : http);
	protocol.request({
			host: url.host,
			port: url.port || (url.protocol === "https:" ? 443 : 80),
			path: url.pathname,
			method: "POST",
			headers:{
				accept: "*/*",
				"Content-Type": "application/json",
				"Content-Length": 0
			}
		},
		function(response)
		{
			var body = "";
			response.on("data", function(chunk)
			{
				body += chunk;
			});
			response.on("end", function()
			{
				var data;
				try
				{
					data = JSON.parse(body);
					if (!data.response || !data.response.server_time)
					{
						return complete({message:"Invalid time response from Steam"});
					}

					var servertime = parseInt(data.response.server_time) * 1000;
					var offset = SteamAuth.Offset = new Date().getTime() - servertime;

					complete(null, offset);
				}
				catch (ex)
				{
					complete({message:"Invalid response: " + body});
				}
			});
		}
	).on("error", function(err)
	{
		complete(err);
	}).end();
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
 * e.g. var code = new SteamAuth().calculateCode("STK7746GVMCHMNH5FBIAQXGPV3I7ZHRG");
 *      var code = new SteamAuth({secret:"STK7746GVMCHMNH5FBIAQXGPV3I7ZHRG", encoding:"base32"}).calculateCode();
 *
 * @param options Either Base32 (RFC3548) encoded secret key or options object {secret:encoded secret key,
 *                time:time to use in ms, encoding:base32|base64|hex encoding of secret}
 * @param time optional time in ms
 * @returns {string} 5 character SteamGuard code
 */
SteamAuth.prototype.calculateCode = function(options, time)
{
	if (!options)
	{
		options = {};
	}
	else if (typeof options === "string")
	{
		options = {secret:options};
	}
	if (time)
	{
		options.time = time;
	}

	var secret = options.secret || this._secret;

	// convert secret from Base32 to buffer
	var secretBuffer = decodeSecretToBuffer(secret, options.encoding);

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

module.exports = SteamAuth;
