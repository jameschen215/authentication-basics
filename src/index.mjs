// index.mjs
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { Pool } from 'pg';
import url from 'url';
import path from 'path';
import bcrypt from 'bcrypt';

// configure path
const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = 3000;

// db configure
const pool = new Pool({
	database: 'top_users',
	host: 'localhost',
	user: 'chenjian',
	password: 'jj',
	port: 5432,
});

// app
const app = express();
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(
	session({
		secret: 'my secret',
		resave: false,
		saveUninitialized: false,
	})
);
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

// authentication
passport.use(
	new LocalStrategy(async (username, password, done) => {
		try {
			const { rows } = await pool.query(
				`SELECT * FROM users WHERE username = $1`,
				[username]
			);
			const user = rows[0];

			if (!user) {
				return done(null, false, { message: 'Incorrect username' });
			}

			const matched = await bcrypt.compare(password, user.password);
			if (!matched) {
				return done(null, false, { message: 'Incorrect password' });
			}

			return done(null, user);
		} catch (error) {
			return done(error);
		}
	})
);

passport.serializeUser((user, done) => {
	done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
	try {
		const { rows } = await pool.query('SELECT * FROM users WHERE id = $1', [
			id,
		]);
		const user = rows[0];

		done(null, user);
	} catch (error) {
		done(error);
	}
});

app.use((req, res, next) => {
	res.locals.currentUser = req.user;
	next();
});

// routes
app.get('/', (req, res) => res.render('index'));
app.get('/sign-up', (req, res) => res.render('sign-up-form'));
app.get('/log-in', (req, res) => res.render('login-form'));

app.post('/sign-up', async (req, res, next) => {
	try {
		const hashedPassword = await bcrypt.hash(req.body.password, 10);
		await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [
			req.body.username,
			hashedPassword,
		]);

		res.redirect('/');
	} catch (error) {
		return next(error);
	}
});

app.post(
	'/log-in',
	passport.authenticate('local', { successRedirect: '/', failureRedirect: '/' })
);

app.get('/log-out', (req, res, next) => {
	req.logOut((err) => {
		if (err) return next(err);
		res.redirect('/');
	});
});

// start server
app.listen(PORT, (error) => {
	if (error) {
		throw error;
	}

	console.log(`App listening on port ${PORT}`);
});
