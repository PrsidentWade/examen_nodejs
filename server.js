const express = require('express');
const pool = require('./models/db');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'secretkey123',
    resave: false,
    saveUninitialized: false
}));

// Middlewares d'authentification
function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/login');
}
function isAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') return next();
    res.status(403).send('Accès refusé');
}

// Page d'inscription
app.get('/register', (req, res) => {
    res.render('register', { error: null });
});

// Traitement inscription
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        await pool.query(
            'INSERT INTO "user" (username, password, role) VALUES ($1, $2, $3)',
            [username, hashedPassword, role]
        );
        res.redirect('/login');
    } catch (err) {
        res.render('register', { error: 'Nom d\'utilisateur déjà utilisé' });
    }
});

// Page de connexion
app.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// Traitement connexion
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const result = await pool.query('SELECT * FROM "user" WHERE username = $1', [username]);
    const user = result.rows[0];
    if (user && await bcrypt.compare(password, user.password)) {
        req.session.user = { id: user.id, username: user.username, role: user.role };
        res.redirect('/');
    } else {
        res.render('login', { error: 'Identifiants invalides' });
    }
});

// Déconnexion
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});
app.get('/', isAuthenticated, async (req, res) => {
    const result = await pool.query('SELECT * FROM etudiants ORDER BY id DESC');
    const stats = await pool.query('SELECT sexe, COUNT(*) as count FROM etudiants GROUP BY sexe');
    res.render('index', {
        etudiants: result.rows,
        user: req.session.user,
        stats: stats.rows // <-- Ajout de stats ici
    });
});

// Accueil - Liste des étudiants (connecté)
app.get('/', isAuthenticated, async (req, res) => {
    const result = await pool.query('SELECT * FROM etudiants ORDER BY id DESC');
    res.render('index', { etudiants: result.rows, user: req.session.user });
});

// Formulaire ajout (admin uniquement)
app.get('/add', isAuthenticated, isAdmin, (req, res) => {
    res.render('add');
});

// Ajouter étudiant (admin uniquement)
app.post('/add', isAuthenticated, isAdmin, async (req, res) => {
    const { matricule, nom, prenom, datenaissance, filiere, universite, adresse, sexe, nationalite } = req.body;
    await pool.query(
        'INSERT INTO etudiants (matricule, nom, prenom, datenaissance, filiere, universite, adresse, sexe, nationalite) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
        [matricule, nom, prenom, datenaissance, filiere, universite, adresse, sexe, nationalite]
    );
    res.redirect('/');
});

// Formulaire modification (admin uniquement)
app.get('/edit/:id', isAuthenticated, isAdmin, async (req, res) => {
    const result = await pool.query('SELECT * FROM etudiants WHERE id = $1', [req.params.id]);
    res.render('edit', { etudiant: result.rows[0] });
});

// Modifier étudiant (admin uniquement)
app.post('/edit/:id', isAuthenticated, isAdmin, async (req, res) => {
    const { matricule, nom, prenom, datenaissance, filiere, universite, adresse, sexe, nationalite } = req.body;
    await pool.query(
        'UPDATE etudiants SET matricule=$1, nom=$2, prenom=$3, datenaissance=$4, filiere=$5, universite=$6, adresse=$7, sexe=$8, nationalite=$9 WHERE id=$10',
        [matricule, nom, prenom, datenaissance, filiere, universite, adresse, sexe, nationalite, req.params.id]
    );
    res.redirect('/');
});

// Supprimer étudiant (admin uniquement)
app.post('/delete/:id', isAuthenticated, isAdmin, async (req, res) => {
    await pool.query('DELETE FROM etudiants WHERE id = $1', [req.params.id]);
    res.redirect('/');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Serveur lancé sur le port http://localhost:${PORT}`));