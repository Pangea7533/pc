const express = require("express");
const app = express();
const fs = require("fs");
const crypto = require("crypto");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const engine = require("jsembedtemplateengine");
const http = require("http").Server(app);
const he = require("he");
const jimp = require("jimp");
let productionEnvironment = false; // Makes JSON files smaller
if (process.env.NODE_ENV == "production") productionEnvironment = true;
let randomAuthTokens = [];
let manageAuthTokens = {};
let shutAbility = 0;
let availableCurrencies = [
//	"TST"
];
let privateAvailableCurrencies = availableCurrencies.map(a => require(__dirname + "/integr8/" + a));
let miningTasks = {};
const mineutils = require("./mining/mineutils");
var urlencodedParser = bodyParser.urlencoded({ extended: false })

setInterval(function() {
	for (let token in randomAuthTokens) if (Date.now() >= randomAuthTokens[token].expireStamp) randomAuthTokens.splice(token, 1);
});

setInterval(function() {
	manageAuthTokens.length = 0;
}, 900000)

app.use(cookieParser());
app.use(bodyParser.urlencoded({
	extended: true
}));
app.use(bodyParser.json());
engine(app, {
	embedOpen: "<nodejs-embed>",
	embedClose: "</nodejs-embed>"
});
app.set('views', '.')
app.set('view engine', 'jsembeds');

const user = {
	getUserByPubkey: function (pubk) {
		const username = Object.keys(this.db).find(user => this.db[user].pubkey == pubk);
		if (username) return { username: username, object: this.db[username] };
		return null;
	},
	getUserBySecret: function (secr) {
		const username = Object.keys(this.db).find(user => this.db[user].secret == secr);
		if (username) return { username: username, object: this.db[username] };
		return null;
	},
	getUserByName: (username) => user.db[username],
	setUser: function (name, data) {
		let snaps = this.db;
		snaps[name] = data;
		this.db = snaps;
	},
	deleteUser: function (name) {
		let snaps = this.db;
		delete snaps[name];
		this.db = snaps;
	},
	get db() {
		return JSON.parse(fs.readFileSync(__dirname + "/users.json"));
	},
	set db(val) {
		return fs.writeFileSync(__dirname + "/users.json", productionEnvironment ? JSON.stringify(val) : JSON.stringify(val, null, "\t"));
	}
}

function RequiredUserMiddleware(req, res, next) {
	if (req.cookies.token && user.getUserBySecret(req.cookies.token)) {
		req.user = user.getUserBySecret(req.cookies.token);
		if ((Date.now() - req.user.object.lastLogin) >= 86400000) {
			let currentUser = structuredClone(req.user.object);
			currentUser.transactions.push({
				money: 100,
				sender: "system",
				recipient: req.user.username,
				timestamp: Date.now(),
				token: "DAILY-" + crypto.randomBytes(32).toString("hex"),
				description: "Daily bonus for using PCCurrency."
			});
			currentUser.lastLogin = Date.now();
			currentUser.placeUsages = 0;
			user.setUser(req.user.username, currentUser);
		}
		return next();
	}
	res.clearCookie("token");
	res.redirect("/");
}

function RequiredNoUserMiddleware(req, res, next) {
	if (!req.cookies.token || !user.getUserBySecret(req.cookies.token || "")) return next();
	res.redirect("/home");
}

function JustRecognizeUserMiddleware(req, res, next) {
	req.user = user.getUserBySecret(req.cookies.token || "");
	next();
}

function calculateBalanceFromTransactions(transactions) {
	let balance = 0;
	for (let i = 0; i < transactions.length; i++) {
		balance += transactions[i].money;
	}
	return balance;
}

app.get("/", RequiredNoUserMiddleware, (req, res) => res.status(401).sendFile(__dirname + "/logon.html"));
app.get("/register", RequiredNoUserMiddleware, (req, res) => res.status(401).sendFile(__dirname + "/register.html"));

app.get("/logout", RequiredUserMiddleware, function (req, res) {
	res.clearCookie("token");
	res.redirect("/");
});

app.post("/imagination/register", function (req, res) {
	if (!req.body.pubkey) return res.status(400).send("Bad request!");
	if (!req.body.username) return res.status(400).send("Bad request!");

	if (user.getUserByName(req.body.username)) return res.status(400).send("That user already exists! Try another one.");
	if (user.getUserByPubkey(req.body.pubkey)) return res.status(400).send("That public key is already taken! Try another one.");
	if (req.body.username == "system") return res.status(400).send("You attempted to impersonate the system user. You can't do that!");
	if (req.body.pubkey?.length < 789) return res.status(400).send("That public key is already too small! Try another one, with at least 4096 bits.");
	try {
		user.setUser(req.body.username, {
			pubkey: req.body.pubkey,
            secret: crypto.randomBytes(32).toString("hex"),
			sales: [],
			transactions: [],
			lastLogin: Date.now(),
			placeUsages: 0
		});
	} catch {
		return res.status(500).send("Something went terribly wrong when creating your account");
	}
	res.send("OK");
});

app.get("/imagination/getEncryptedSecret", RequiredNoUserMiddleware, function (req, res) {
	if (!user.getUserByPubkey(req.query.pubkey)) return res.status(401).send("Invalid public key: unregistered or blocked user?");
	try {
		res.send(crypto.publicEncrypt({
			key: req.query.pubkey,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256'
		}, Buffer.from(user.getUserByPubkey(req.query.pubkey).object.secret, "utf-8")).toString("base64"));
	} catch {
		res.status(500).send("Something went terribly wrong when encrypting the secret token");
	}
});

app.use("/imagination", express.static(__dirname + "/imagination"));

app.get("/home", RequiredUserMiddleware, function(req, res) {
	var sales = req.user.object.sales;
	var temp = ""
	sales.forEach((sale) => {
		var buyer = sale.sender
		var token = sale.token
		var description = sale.description
		var time = new Date(sale.timestamp).toString()
		temp += `Sold 1 ${description} to ${buyer} at ${time} (${token})<br> `
	})
    res.render(__dirname + "/index.jsembeds", {
		sales: temp,
		username: he.encode(req.user.username),
		currencyAmount: calculateBalanceFromTransactions(req.user.object.transactions).toFixed(2),
		dailyPixAmount: req.user.object.placeUsages,
		isologon: new Date(req.user.object.lastLogin + 86400000).toISOString(),
		currentDifficulty: req.user.object.miningDifficulty || 4
	});
});

app.get("/hallOfTransactions", RequiredUserMiddleware, function(req, res) {
	res.render(__dirname + "/hallOfTransactions.jsembeds", {
		transactions: req.user.object.transactions,
		reverseOrder: !(req.query.chronological == "1")
	});
});

app.get("/give", RequiredUserMiddleware, function(req, res) {
	res.render(__dirname + "/give.jsembeds", {
		username: he.encode(req.user.username)
	});
});

app.get("/outNetworkGive", RequiredUserMiddleware, function(req, res) {
	res.render(__dirname + "/outNetworkGive.jsembeds", {
		username: he.encode(req.user.username)
	});
});

app.get("/style.css", (req, res) => res.sendFile(__dirname + "/stylesus.css"));
app.get("/stylesus.css", (req, res) => res.sendFile(__dirname + "/style.css"));

app.get("/transactionAuth", RequiredUserMiddleware, function(req, res) {
	let tok = crypto.randomBytes(32).toString("hex");
	randomAuthTokens.push({
		token: tok,
		expireStamp: Date.now() + 10000,
		username: req.user.username
	});
	try {
		res.send(crypto.publicEncrypt({
			key: req.user.object.pubkey,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256'
		}, Buffer.from(tok, "utf-8")).toString("base64"));
	} catch {
		res.status(500).send("Something went terribly wrong when encrypting the secret token");
	}
});

app.post("/inNetworkTransaction", RequiredUserMiddleware, function(req, res) {
	if (!req.body.recipient) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.money) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.token) return res.status(400).send("Incomplete transaction structure.");
	if (typeof req.body.description !== "string") return res.status(400).send("Incomplete or wrong transaction structure.");
	if (randomAuthTokens.find(token => token.token == req.body.token)?.username != req.user.username) return res.status(401).send("Unauthorized transaction.");
	randomAuthTokens = randomAuthTokens.filter(token => token.token != req.body.token);
	if (parseFloat(req.body.money) < 0) return res.status(400).send("Invalid transaction amount.");
	if (isNaN(req.body.money)) return res.status(400).send("Invalid transaction amount.");
	if (!isFinite(req.body.money)) return res.status(400).send("Invalid transaction amount.");
	if (parseFloat(req.body.money) > calculateBalanceFromTransactions(req.user.object.transactions)) return res.status(400).send("Insufficient funds.");
	if (req.body.recipient == req.user.username) return res.status(400).send("Sending currency to yourself is impossible.");
	if (!user.getUserByName(req.body.recipient)) return res.status(404).send("Recipient does not exist.");
	let currentUser = structuredClone(req.user.object);
	let recipient = structuredClone(user.getUserByName(req.body.recipient));
	currentUser.transactions.push({
		money: parseFloat(req.body.money) * -1,
		sender: req.user.username,
		recipient: req.body.recipient,
		timestamp: Date.now(),
		token: req.body.token,
		description: req.body.description || ""
	});
	recipient.transactions.push({
		money: parseFloat(req.body.money),
		sender: req.user.username,
		recipient: req.body.recipient,
		timestamp: Date.now(),
		token: req.body.token,
		description: req.body.description || ""
	});
	req.user.object = currentUser;
	user.setUser(req.body.recipient, recipient);
	user.setUser(req.user.username, req.user.object);
	res.send("OK");
});

app.post("/notify", RequiredUserMiddleware, function(req, res) {
	let currentUser = structuredClone(req.user.object);
	let recipient = structuredClone(user.getUserByName(req.body.recipient));
	recipient.sales.push({
		money: parseFloat(req.body.money),
		sender: req.user.username,
		recipient: req.body.recipient,
		timestamp: Date.now(),
		token: req.body.token,
		description: req.body.description || ""
	});
	user.setUser(req.body.recipient, recipient);
	res.send("OK");
});

app.post("/outNetworkTransaction", RequiredUserMiddleware, async function(req, res) {
	if (!req.body.recipient) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.money) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.token) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.currency) return res.status(400).send("Incomplete transaction structure.");
	if (typeof req.body.description !== "string") return res.status(400).send("Incomplete or wrong transaction structure.");
	if (!availableCurrencies.includes(req.body.currency)) return res.status(404).send("Currency does not exist");
	if (randomAuthTokens.find(token => token.token == req.body.token)?.username != req.user.username) return res.status(401).send("Unauthorized transaction.");
	randomAuthTokens = randomAuthTokens.filter(token => token.token != req.body.token);
	if (parseFloat(req.body.money) < 0) return res.status(400).send("Invalid transaction amount.");
	if (isNaN(req.body.money)) return res.status(400).send("Invalid transaction amount.");
	if (!isFinite(req.body.money)) return res.status(400).send("Invalid transaction amount.");
	let currency = privateAvailableCurrencies[availableCurrencies.indexOf(req.body.currency)];
	if (parseFloat(req.body.money) * currency.rate > calculateBalanceFromTransactions(req.user.object.transactions)) return res.status(400).send("Insufficient funds.");
	
	let response = await fetch(currency.transactionServer + "outNetworkTransactionRecieve", {
		method: "POST",
		headers: {
			"Content-Type": "application/json"
		},
		body: JSON.stringify({
			sender: req.user.username,
			recipient: req.body.recipient,
			money: parseFloat(req.body.money),
			token: req.body.token,
			timestamp: Date.now(),
			currency: req.body.currency,
			currencySecret: currency.secret,
			description: req.body.description || ""
		})
	});
	if (!response.ok) return res.status(response.status).send("Remote server error: " + (await response.text()));
	let currentUser = structuredClone(req.user.object);
	currentUser.transactions.push({
		money: parseFloat(req.body.money) * currency.rate * -1,
		sender: req.user.username,
		recipient: "REMOTE-" + req.body.currency + "-" + req.body.recipient,
		timestamp: Date.now(),
		token: "REMOTE-" + req.body.token,
		description: req.body.description || ""
	});
	req.user.object = currentUser;
	user.setUser(req.user.username, req.user.object);
	res.send("OK");
});

function shutAbilityZero() {
	return new Promise(function(resolve) {
		let id = setInterval(function() {
			if (shutAbility == 0) {
				clearInterval(id);
				resolve();
			}
		});
	});
}

app.get("/place", RequiredUserMiddleware, (req, res) => res.sendFile(__dirname + "/place.html"));
app.get("/place.png", RequiredUserMiddleware, async function(req, res) {
	await shutAbilityZero();
	res.sendFile(__dirname + "/pixboard.png");
});

app.post("/place", RequiredUserMiddleware, async function(req, res) {
	await shutAbilityZero();
	let pic;
	try {
		pic = await jimp.read(__dirname + "/pixboard.png");
	} catch (e) {
		return res.status(500).send("Something went terribly wrong when reading the pixboard");
	}
	let properX = Math.floor(parseFloat(req.body.x) / 16) * 16;
	let properY = Math.floor(parseFloat(req.body.y) / 16) * 16;
	for (let y = properY; y < properY + 16; y++) {
		for (let x = properX; x < properX + 16; x++) {
			pic.setPixelColor(jimp.cssColorToHex(req.body.color), x, y);
		}
	}
	shutAbility++;
	await pic.writeAsync(__dirname + "/pixboard.png");
	shutAbility--;
	req.user.object.placeUsages++;
	if (req.user.object.placeUsages <= 1024) {
		req.user.object.transactions.push({
			money: 1.0,
			sender: "system",
			recipient: req.user.username,
			timestamp: Date.now(),
			token: "PLACE-" + crypto.randomBytes(32).toString("hex"),
			description: "Usage of PCCurrency Place - a place for crazy ideas of users."
		});
	}
	await user.setUser(req.user.username, req.user.object);
	res.send("OK");
});
app.get("/datify.js", (req, res) => res.sendFile(__dirname + "/datify.js"));

app.get("/manageAccount", RequiredUserMiddleware, function (req, res) {
	if (req.query.security_token) {
		if (!manageAuthTokens.hasOwnProperty(req.query.security_token)) return res.redirect("/manageAccount");
		if (manageAuthTokens[req.query.security_token] != req.user.username) return res.redirect("/manageAccount");
		return res.render(__dirname + "/manageAccount.jsembeds", {
			security_token: req.query.security_token
		});
	}
	return res.sendFile(__dirname + "/manageAccountPreEnvironment.html");
});

app.get("/manageAccountSecurityToken", RequiredUserMiddleware, function (req, res) {
	try {
		let tst = crypto.randomBytes(64).toString("hex");
		manageAuthTokens[tst] = req.user.username;
		res.send(crypto.publicEncrypt({
			key: req.user.object.pubkey,
			padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
			oaepHash: 'sha256'
		}, Buffer.from(tst, "utf-8")).toString("base64"));
	} catch {
		res.status(500).send("Something went terribly wrong when encrypting the secret token");
	}
});

app.get("/manageAccount/revokeToken", RequiredUserMiddleware, function (req, res) {
	if (!req.query.security_token) return res.redirect("/home");
	if (!manageAuthTokens.hasOwnProperty(req.query.security_token)) return res.redirect("/home");
	if (manageAuthTokens[req.query.security_token] != req.user.username) return res.redirect("/home");
	delete manageAuthTokens[req.query.security_token];
	res.redirect("/");
});

app.get("/manageAccount/changeKeypair", RequiredUserMiddleware, function (req, res) {
	if (!req.query.security_token) return res.redirect("/manageAccount");
	if (!manageAuthTokens.hasOwnProperty(req.query.security_token)) return res.redirect("/manageAccount");
	if (manageAuthTokens[req.query.security_token] != req.user.username) return res.redirect("/manageAccount");
	if (!req.query.pubkey) return res.status(400).send("Bad request!");
	if (user.getUserByPubkey(req.query.pubkey)) return res.status(400).send("That public key is already taken! Try another one.");

	delete manageAuthTokens[req.query.security_token];
	try {
		req.user.object.pubkey = req.query.pubkey;
		req.user.object.secret = crypto.randomBytes(32).toString("hex");
		user.setUser(req.user.username, req.user.object);
	} catch {
		return res.status(500).send("Something went terribly wrong when changing your pubkey");
	}
	res.send("OK");
});

app.get("/manageAccount/changeSecret", RequiredUserMiddleware, function (req, res) {
	if (!req.query.security_token) return res.redirect("/manageAccount");
	if (!manageAuthTokens.hasOwnProperty(req.query.security_token)) return res.redirect("/manageAccount");
	if (manageAuthTokens[req.query.security_token] != req.user.username) return res.redirect("/manageAccount");
	req.user.object.secret = crypto.randomBytes(32).toString("hex");
	user.setUser(req.user.username, req.user.object)
	delete manageAuthTokens[req.query.security_token];
	res.redirect("/manageAccount");
});

app.get("/marketplace", RequiredUserMiddleware, function (req, res) {
	res.writeHead(200, { 'Content-Type': 'text/html' });
	res.write("<link rel=\"stylesheet\" href=\"/style.css\"><a href=\"/\">Return</a> <a href=\"/createlisting\">Create a listing</a>\n<h1>Marketplace listings</h1><hr><br><ul>")
	var database = JSON.stringify(user.getUserByName("marketplace").services).toString()
	var databases = JSON.parse(database)
	databases.forEach((temp) => {
		var data = JSON.stringify(temp);
		var template = `<li><a href="http://127.0.0.1:4599/streamlinedPayment?money=${temp.price}&vendor=${temp.seller}&vendorUsername=${temp.seller}&service=${temp.description}">${temp.description} (${temp.price} PC)</a></li>`
		res.write(template+" <br>")
	})
	res.write("</ul>")
	res.end()
});

app.get("/createlisting", RequiredUserMiddleware, function (req, res) {
	res.writeHead(200, { 'Content-Type': 'text/html' });
	res.write("<link rel=\"stylesheet\" href=\"/style.css\"><a href=\"/\">Return</a>\n<h1>Create a marketplace listing</h1><hr><br><form action='/createlisting' method=\"post\"><input class='textinput' name='title' id='title'> Listing title</input><br><br><input class='textinput' name='price' id='price'> Listing price</input><br><br><button class='btn' type='submit'>Submit</button></button></form>")
res.end()
});

app.post('/createlisting', RequiredUserMiddleware, urlencodedParser, function (req, res) {
	// Prepare output in JSON format
	var price1 = req.body.price
	var title1 = req.body.title
	var user1 = req.user.username

	var obj = `{"price": "${price1}","description": "${title1}","seller": "${user1}"}`
	var json = require('./users.json');
	//user.setUser("marketplace", req.user.object);
	json.marketplace.services.push(JSON.parse(obj))
	fs.writeFileSync(__dirname+"/users.json", JSON.stringify(json, null, 2));
	res.end("ok")
})
app.get("/manageAccount/removeAccount", RequiredUserMiddleware, function (req, res) {
	if (!req.query.security_token) return res.redirect("/manageAccount");
	if (!manageAuthTokens.hasOwnProperty(req.query.security_token)) return res.redirect("/manageAccount");
	if (manageAuthTokens[req.query.security_token] != req.user.username) return res.redirect("/manageAccount");
	user.deleteUser(req.user.username);
	delete manageAuthTokens[req.query.security_token];
	res.redirect("/");
});
//http://127.0.0.1:4599/streamlinedPayment?money=1&vendor=susPC&vendorUsername=Pangea7533&service=ddos
app.get("/streamlinedPayment", RequiredUserMiddleware, function(req, res) {
	if (!req.query.money) return res.redirect("/");
	if (!req.query.vendor) return res.redirect("/");
	if (!req.query.vendorUsername) return res.redirect("/");
	if (!req.query.service) return res.redirect("/");
	let ref = req.hostname;
	try {
		ref = new URL(req.headers.referer || "https://" + req.hostname).hostname;
	} catch {}
	res.render(__dirname + "/streamlinedPayment.jsembeds", {
		username: he.encode(req.user.username),
		hasEnoughBalance: calculateBalanceFromTransactions(req.user.object.transactions) >= parseFloat(req.query.money) ? "" : "title=\"Insufficient funds!\"",
		vendor: he.encode(req.query.vendor),
		vendrUsername: he.encode(req.query.vendorUsername),
		vendrUsernmeJS: JSON.stringify(req.query.vendorUsername),
		money: parseFloat(req.query.money).toFixed(2),
		monyJS: parseFloat(req.query.money),
		referrer: ref,
		service: he.encode(req.query.service),
		servceJS: JSON.stringify(req.query.service),
		currencyAmount: calculateBalanceFromTransactions(req.user.object.transactions).toFixed(2)
	})
});

app.get("/api", RequiredUserMiddleware, (req, res) => res.sendFile(__dirname + "/docs.html"));
app.get("/api/balance", RequiredUserMiddleware, (req, res) => res.json(calculateBalanceFromTransactions(req.user.object.transactions)));
app.get("/api/transactions", RequiredUserMiddleware, (req, res) => res.json(req.user.object.transactions));
app.get("/api/transactions/:id", RequiredUserMiddleware, (req, res) => res.json(req.user.object.transactions[req.params.id]));
app.get("/api/placeUsage", RequiredUserMiddleware, (req, res) => res.json(req.user.object.placeUsages));
app.get("/api/username", RequiredUserMiddleware, (req, res) => res.json(req.user.username));
app.get("/api/availableCurrencies", RequiredUserMiddleware, (req, res) => res.json(availableCurrencies));
app.get("/api/dailyReset", RequiredUserMiddleware, (req, res) => res.json(req.user.object.lastLogin + 86400000));
app.get("/api/currencyEquivalents", RequiredUserMiddleware, function(req, res) {
	if (req.query.currency) {
		if (req.query.money) return res.json(parseFloat(req.query.money) * privateAvailableCurrencies[availableCurrencies.indexOf(req.query.currency)].rate);
		return res.json(privateAvailableCurrencies[availableCurrencies.indexOf(req.query.currency)].rate);
	}
	if (req.query.money) return res.json(privateAvailableCurrencies.map(a => parseFloat(req.query.money) * a.rate));
	res.json(privateAvailableCurrencies.map(a => a.rate));
});

app.post("/api/outNetworkTransactionSend", function(req, res) {
	if (!req.body.recipient) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.sender) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.money) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.token) return res.status(400).send("Incomplete transaction structure.");
	if (!req.body.currencySecret) return res.status(400).send("Incomplete transaction structure.");
	if (typeof req.body.description !== "string") return res.status(400).send("Incomplete or wrong transaction structure.");
	if (parseFloat(req.body.money) < 0) return res.status(400).send("Invalid transaction amount.");
	if (isNaN(req.body.money)) return res.status(400).send("Invalid transaction amount.");
	if (!isFinite(req.body.money)) return res.status(400).send("Invalid transaction amount.");
	let currency = null;
	for (let cur in privateAvailableCurrencies) if (privateAvailableCurrencies[cur].secret == req.body.currencySecret) currency = availableCurrencies[cur];
	if (!currency) return res.status(401).send("Outgoing request is not authenticated.");
	if (!user.getUserByName(req.body.recipient)) return res.status(404).send("Recipient does not exist.");
	let currencyInfo = privateAvailableCurrencies[availableCurrencies.indexOf(currency)];
	let newUser = user.getUserByName(req.body.recipient);
	newUser.transactions.push({
		money: req.body.money * currencyInfo.rate,
		sender: "REMOTE-" + currency + "-" + req.body.sender,
		recipient: req.body.recipient,
		timestamp: Date.now(),
		token: "REMOTE-" + req.body.token,
		description: req.body.description || ""
	})
	user.setUser(req.body.recipient, newUser);
	res.send("OK");
});

app.get("/difficulty", RequiredUserMiddleware, function(req, res) {
	if (req.query.difficulty) {
		if (isNaN(parseInt(req.query.difficulty))) return res.status(400).send("Invalid difficulty!");
		if (!isFinite(parseInt(req.query.difficulty))) return res.status(400).send("Invalid difficulty!");
		if (parseInt(req.query.difficulty) < 1) return res.status(400).send("Invalid difficulty!");
		if (parseInt(req.query.difficulty) > 32) return res.status(400).send("Invalid difficulty!");
		req.user.object.miningDifficulty = parseInt(req.query.difficulty);
		user.setUser(req.user.username, req.user.object);
		return res.redirect("/");
	}
	res.render(__dirname + "/difficulty.jsembeds", {
		currentDifficulty: req.user.object.miningDifficulty || 4
	})
})

app.get("/api/task", RequiredUserMiddleware, function(req, res) {
	if (req.query.code) {
		if (!miningTasks.hasOwnProperty((req.query.thread || "0") + "_" + req.user.username)) return res.status(400).send("A mining session was not started.") 
		if (mineutils.verify(miningTasks[(req.query.thread || "0") + "_" + req.user.username].data, miningTasks[(req.query.thread || "0") + "_" + req.user.username].difficulty, req.query.code)) {
			req.user.object.transactions.push({
				money: 0.01 * miningTasks[(req.query.thread || "0") + "_" + req.user.username].difficulty.length,
				sender: "system",
				recipient: req.user.username,
				timestamp: Date.now(),
				token: "MINE-" + crypto.randomBytes(32).toString("hex"),
				description: "Mined " + miningTasks[(req.query.thread || "0") + "_" + req.user.username].data + " to nonce " + req.query.code + " with difficulty " + miningTasks[(req.query.thread || "0") + "_" + req.user.username].difficulty.length
			});
			delete miningTasks[(req.query.thread || "0") + "_" + req.user.username];
			user.setUser(req.user.username, req.user.object);
			return res.send("OK");
		}
		return res.status(400).send("WRONG!");
	}
	if (!miningTasks[(req.query.thread || "0") + "_" + req.user.username]) miningTasks[(req.query.thread || "0") + "_" + req.user.username] = {
		data: crypto.randomBytes(32).toString("base64"),
		difficulty: "0".repeat(req.user.object.miningDifficulty || 4)
	}
	res.json(miningTasks[(req.query.thread || "0") + "_" + req.user.username]);
});

app.get("/mining", RequiredUserMiddleware, (req, res) => res.sendFile(__dirname + "/mining.zip"))

http.listen(4599, function () {
	console.log("HTTP at :4599");
});