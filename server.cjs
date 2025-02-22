require("dotenv").config();
const express = require("express");
const bodyparser = require("body-parser");
const bcrypt = require("bcrypt");
const cors = require("cors");
const knex = require("knex");
const jwt = require("jsonwebtoken");

const access = process.env.ACCESS_TOKEN_SECRET;
const refresh = process.env.REFRESH_TOKEN_SECRET;

// const db = knex({
// 	client: "pg",
// 	connection: {
// 		host: "127.0.0.1",
// 		user: "postgres",
// 		password: "Wiggles123",
// 		database: "game-next",
// 	},
// });

const db = knex({
	client: "pg",
	connection: {
		connectionString: process.env.RENDER_DATABASE_URL,
		ssl: { rejectUnauthorized: false },
		host: process.env.RENDER_HOST,
		port: 5432,
		user: process.env.RENDER_USER,
		password: process.env.RENDER_PASSWORD,
		database: process.env.RENDER_DATABASE,
	},
});

const app = express();
app.use(bodyparser.json());
app.use(cors());

app.get("/", (req, res) => {
	res.json("success");
});

const verifyJWT = (req, res, next) => {
	const authHeader = req.headers["authorization"];
	if (!authHeader) return res.sendStatus(400);
	const token = authHeader?.split(" ")[1];
	jwt.verify(token, access, (err, user) => {
		if (err) return res.status(403).json("bad token");
		req.user = user;
		next();
	});
};

const generateAccess = (user) => jwt.sign(user, access, { expiresIn: "5m" });

app.post("/token", (req, res) => {
	const refreshToken = req.body.token;
	db.select("*")
		.from("login")
		.where({ refresh: refreshToken })
		.then((data) => {
			jwt.verify(data[0].refresh, refresh, (err, user) => {
				if (err) return res.status(403).json("bad token");
				const accessToken = generateAccess({ email: user.email });
				res.json(accessToken);
			});
		})
		.catch((err) => res.status(403).json("refreshToken is incorrect"));
});

app.get("/post", verifyJWT, (req, res) => {
	db.select("*")
		.from("users")
		.then((data) => {
			res.json(data.filter((user) => user.email === req.user.email));
		});
});

app.get("/use", (req, res) => {
	db("login")
		.returning("*")
		.then((data) => res.json(data));
});

app.post("/signin", (req, res) => {
	const { email, password } = req.body;
	if (!email || !password) {
		res.status(400).json("incorrect form submission");
	}
	db.select("email", "hash")
		.from("login")
		.where({ email: email })
		.then((data) => {
			const isValid = bcrypt.compareSync(password, data[0].hash);
			if (isValid) {
				return db
					.select("*")
					.from("users")
					.where("email", "=", email)
					.then((data) => {
						// res.json(user[0]);
						const email = data[0].email;
						const user = { email: email };
						const accessToken = generateAccess(user);
						const refreshToken = jwt.sign(user, refresh, { expiresIn: "6h" });
						db.select("*")
							.from("login")
							.where({ email: email })
							.update({ refresh: refreshToken })
							.returning("*")
							.then((data) => {
								res.json({
									accessToken: accessToken,
									refreshToken: data[0].refresh,
								});
							});
					})
					.catch((err) => res.status(400).json("unable to get user"));
			} else {
				res.status(400).json("wrong cridentials");
			}
			// }
		})
		.catch((err) => res.status(400).json("wrong cridentials"));
});

app.post("/logout", (req, res) => {
	const { email } = req.body;
	db("login")
		.where({ email: email })
		.update({ refresh: null })
		.returning("*")
		.then((data) => res.json("log out seccessful"));
});

app.delete("/del", (req, res) => {
	const { name } = req.body;
	db("login")
		.where({ email: name })
		.del()
		.returning("*")
		.then((data) => res.json(data[0]));
});

app.post("/register", (req, res) => {
	const { name, email, password } = req.body;
	const hash = bcrypt.hashSync(password, 10);
	if (!name || !email || !password) {
		res.status(400).json("please fill in info");
	} else {
		db.transaction((trx) => {
			trx
				.insert({
					hash: hash,
					email: email,
				})
				.into("login")
				.returning("email")
				.then((loginEmail) => {
					return trx("users")
						.returning("*")
						.insert({
							email: loginEmail[0].email,
							name: name,
							log: [],
							image: [],
							completion: [],
						})
						.then((user) => {
							res.json(user[0]);
						});
				})
				.then(trx.commit)
				.catch(trx.rollback);
		}).catch((err) => {
			res.status(400).json("unable to register");
			console.log(err);
		});
	}
});

app.put("/log", (req, res) => {
	const { user, log, image, completion } = req.body;
	db("users")
		.where({ name: user })
		.update({ log: log })
		.update({ image: image })
		.update({ completion: completion })
		.returning("*")
		.then((user) => res.json(user[0]));
});

app.listen(4000, () => console.log("app is running"));
